from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

from .curator import AI_PACKET_BULK_MAX_BYTES, AI_PACKET_BULK_MAX_FILES, Curator, human_bytes
from .profiles import ScanProfileManager


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


data_dir = Path(os.environ.get("DATA_DIR", "/config"))
profiles = ScanProfileManager(data_dir)
curator = Curator(
    source=Path(os.environ.get("SOURCE_ROOT", "/source")),
    output=Path(os.environ.get("OUTPUT_ROOT", "/output")),
    quarantine=Path(os.environ.get("QUARANTINE_ROOT", "/quarantine")),
    db_path=Path(profiles.active_profile()["db_path"]),
    allow_actions=env_bool("ALLOW_ACTIONS", False),
    analysis_workers=int(os.environ.get("ANALYSIS_WORKERS", "1")),
    hash_workers=int(os.environ.get("HASH_WORKERS", "1")),
    batch_size=int(os.environ.get("SCAN_BATCH_SIZE", "64")),
    similarity_radius=int(os.environ.get("SIMILARITY_DISTANCE", "6")),
    reference_root=Path(os.environ.get("REFERENCE_ROOT", "/known-good")),
    output_uid=int(os.environ.get("OUTPUT_UID", "99")),
    output_gid=int(os.environ.get("OUTPUT_GID", "100")),
)

app = Flask(__name__)
app.jinja_env.filters["human_bytes"] = human_bytes


@app.get("/")
def index():
    return render_template(
        "index.html", summary=curator.summary(), status=curator.status(),
        active_profile=profiles.active_profile(), profiles=profiles.list_profiles(),
    )


@app.post("/scan")
def scan():
    curator.start_scan()
    return redirect(url_for("index"))


@app.post("/scan/stop")
def stop_scan():
    curator.request_stop()
    return redirect(url_for("index"))


@app.get("/api/status")
def api_status():
    payload = {"status": curator.status(), "active_profile": profiles.active_profile()}
    if request.args.get("include_summary") == "1":
        payload["summary"] = curator.summary()
    return jsonify(payload)


@app.get("/api/reconstruction/workspace")
def api_reconstruction_workspace():
    return jsonify(curator.reconstruction_workspace_state())


@app.post("/api/reconstruction/start")
def api_start_reconstruction():
    try:
        if not curator.start_reconstruction():
            raise RuntimeError("Another scan or analysis job is already running.")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 409
    return jsonify({"ok": True, "status": curator.status()})


@app.post("/api/reconstruction/refresh")
def api_refresh_reconstruction():
    try:
        if not curator.start_reconstruction_plan_refresh():
            raise RuntimeError("Another scan or analysis job is already running.")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 409
    return jsonify({"ok": True, "status": curator.status()})


@app.post("/api/reconstruction/ai/structure")
def api_start_ai_structure():
    values = request.get_json(silent=True) or {}
    try:
        count = curator.start_structure_ai(int(values.get("limit", 12)))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "included": count, "status": curator.status()})


@app.get("/reconstruction/ai/dossier")
def download_ai_reconstruction_dossier():
    try:
        result = curator.export_ai_reconstruction_dossier()
    except Exception as exc:
        return render_template(
            "message.html", title="AI dossier not created", message=str(exc),
        ), 500
    return send_file(
        result["path"], as_attachment=True,
        download_name="reconstruction_ai_dossier.txt", mimetype="text/plain",
    )


@app.post("/api/reconstruction/ai/work-package")
def api_generate_ai_work_package():
    values = request.get_json(silent=True) or {}
    try:
        curator.start_ai_work_package(int(values.get("target_tokens", 40000)))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "status": curator.status()})


@app.get("/api/reconstruction/ai/work-package")
def api_ai_work_package_status():
    return jsonify({"ok": True, "package": curator.ai_work_package_status()})


@app.get("/reconstruction/ai/work-package/<packet_id>")
def download_ai_work_packet(packet_id: str):
    try:
        path = curator.ai_work_packet_path(packet_id)
    except FileNotFoundError:
        abort(404)
    return send_file(path, as_attachment=True, download_name=path.name, mimetype="application/json")


@app.post("/api/reconstruction/ai/work-package/import")
def api_import_ai_work_packet():
    values = request.get_json(silent=True) or {}
    try:
        result = curator.import_ai_work_packet_response(str(values.get("response_text") or ""))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "result": result})


def _uploaded_ai_responses() -> tuple[list[tuple[str, str]], list[str]]:
    uploads = request.files.getlist("files")
    if not uploads:
        raise ValueError("Choose one or more AI response files, or a ZIP containing them.")
    if request.content_length and request.content_length > AI_PACKET_BULK_MAX_BYTES + 1024 * 1024:
        raise ValueError("The upload exceeds the 100 MB bulk import limit.")

    responses: list[tuple[str, str]] = []
    ignored: list[str] = []
    total_bytes = 0

    def add_response(name: str, raw: bytes) -> None:
        nonlocal total_bytes
        if len(responses) >= AI_PACKET_BULK_MAX_FILES:
            raise ValueError(
                f"A bulk import can contain at most {AI_PACKET_BULK_MAX_FILES:,} response files."
            )
        total_bytes += len(raw)
        if total_bytes > AI_PACKET_BULK_MAX_BYTES:
            raise ValueError("The expanded AI responses exceed the 100 MB bulk import limit.")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{name} is not a UTF-8 text response.") from exc
        responses.append((name[:500], text))

    for upload in uploads:
        name = Path(upload.filename or "response").name
        suffix = Path(name).suffix.casefold()
        raw = upload.read()
        if suffix == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
                    entries = [
                        entry for entry in bundle.infolist()
                        if not entry.is_dir() and not entry.filename.startswith("__MACOSX/")
                    ]
                    supported = [
                        entry for entry in entries
                        if Path(entry.filename).suffix.casefold() in {".json", ".txt"}
                    ]
                    ignored.extend(f"{name} / {entry.filename}" for entry in entries if entry not in supported)
                    if sum(entry.file_size for entry in supported) + total_bytes > AI_PACKET_BULK_MAX_BYTES:
                        raise ValueError("The expanded AI responses exceed the 100 MB bulk import limit.")
                    for entry in supported:
                        if entry.flag_bits & 0x1:
                            raise ValueError(f"{name} / {entry.filename} is encrypted and cannot be read.")
                        add_response(f"{name} / {entry.filename}", bundle.read(entry))
            except zipfile.BadZipFile as exc:
                raise ValueError(f"{name} is not a readable ZIP file.") from exc
        elif suffix in {".json", ".txt"}:
            add_response(name, raw)
        else:
            ignored.append(name)
    if not responses:
        raise ValueError("No .json or .txt AI response files were found in the selection.")
    return responses, ignored


@app.post("/api/reconstruction/ai/work-package/bulk-import")
def api_bulk_import_ai_work_packets():
    try:
        responses, ignored = _uploaded_ai_responses()
        result = curator.import_ai_work_packet_responses(responses)
        result["ignored_files"] = ignored[:100]
        result["ignored_file_count"] = len(ignored)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "result": result})


@app.post("/api/reconstruction/ai/batch")
def api_start_ai_batch():
    values = request.get_json(silent=True) or {}
    try:
        count = curator.start_ai_batch(
            str(values.get("media_kind") or "all"), bool(values.get("pending_only", True)),
            bool(values.get("uncertain_only", True)), int(values.get("limit", 100)),
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "included": count, "status": curator.status()})


@app.post("/api/reconstruction/cancel")
def api_cancel_reconstruction():
    requested = curator.request_stop()
    return jsonify({"ok": True, "requested": requested, "status": curator.status()})


@app.post("/api/reconstruction/ai/suggestion/<int:suggestion_id>")
def api_review_ai_suggestion(suggestion_id: int):
    values = request.get_json(silent=True) or {}
    try:
        accepted = curator.review_structure_suggestion(
            suggestion_id, str(values.get("decision") or "rejected"),
        )
        if accepted and not curator.start_reconstruction_plan_refresh():
            raise RuntimeError("Suggestion saved, but another job is already running; apply feedback when it finishes.")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "status": curator.status()})


@app.post("/api/reconstruction/ai/suggestions")
def api_review_ai_suggestions():
    values = request.get_json(silent=True) or {}
    try:
        result = curator.review_structure_suggestions_batch(
            values.get("ids") if isinstance(values.get("ids"), list) else [],
            str(values.get("decision") or "rejected"),
        )
        if result["accepted"] and not curator.start_reconstruction_plan_refresh():
            raise RuntimeError(
                "Suggestions were saved, but another job is running. Apply saved feedback after it finishes."
            )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "result": result, "status": curator.status()})


@app.get("/scans")
def scans():
    return render_template(
        "scans.html", profiles=profiles.list_profiles(), active_profile=profiles.active_profile(),
        status=curator.status(),
    )


@app.post("/scans/create")
def create_scan():
    if curator.status()["running"]:
        return render_template(
            "message.html", title="New scan blocked",
            message="Cancel the active scan and wait for it to stop before creating another saved scan.",
        ), 400
    try:
        profile = profiles.create(request.form.get("name", ""))
        curator.switch_database(Path(profile["db_path"]))
    except Exception as exc:
        return render_template("message.html", title="New scan not created", message=str(exc)), 400
    return redirect(url_for("index"))


@app.post("/scans/switch")
def switch_scan():
    if curator.status()["running"]:
        return render_template(
            "message.html", title="Switch blocked",
            message="Cancel the active scan and wait for it to stop before switching saved scans.",
        ), 400
    try:
        target = profiles.get_profile(request.form.get("profile_id", ""))
        curator.switch_database(Path(target["db_path"]))
        profiles.activate(target["id"])
    except Exception as exc:
        return render_template("message.html", title="Saved scan not loaded", message=str(exc)), 400
    return redirect(url_for("index"))


@app.get("/groups/<kind>")
def groups(kind: str):
    if kind not in {"exact", "similar"}:
        abort(404)
    page = max(1, request.args.get("page", 1, type=int))
    page_size = 25
    rows = curator.group_rows(kind, limit=page_size + 1, offset=(page - 1) * page_size)
    return render_template(
        "groups.html", kind=kind, groups=rows[:page_size], page=page,
        has_next=len(rows) > page_size,
    )


@app.get("/files")
def files():
    category = request.args.get("category") or None
    validation = request.args.get("validation") or None
    known_good_value = request.args.get("known_good")
    known_good = None if known_good_value is None else known_good_value == "1"
    media_kind = request.args.get("media_kind") or None
    page = max(1, request.args.get("page", 1, type=int))
    page_size = 100
    rows = curator.list_files(
        category, validation, known_good, media_kind, limit=page_size + 1,
        offset=(page - 1) * page_size,
    )
    return render_template(
        "files.html", files=rows[:page_size], category=category,
        validation=validation, known_good=known_good, media_kind=media_kind,
        page=page, has_next=len(rows) > page_size,
    )


@app.get("/references")
def references():
    relative = request.args.get("path", ".")
    try:
        browser = curator.browse_reference_directories(relative)
    except Exception as exc:
        return render_template(
            "references.html", browser=None, error=str(exc),
        ), 400
    return render_template("references.html", browser=browser, error=None)


@app.post("/references/add")
def add_reference():
    relative = request.form.get("path", ".")
    try:
        curator.add_reference_selection(relative)
    except Exception as exc:
        return render_template("message.html", title="Folder not selected", message=str(exc)), 400
    return redirect(url_for("references", path=relative))


@app.post("/references/remove")
def remove_reference():
    relative = request.form.get("path", ".")
    try:
        curator.remove_reference_selection(relative)
    except Exception as exc:
        return render_template("message.html", title="Folder not removed", message=str(exc)), 400
    return redirect(url_for("references"))


@app.post("/reset-catalog")
def reset_catalog():
    if request.form.get("confirmation") != "RESET":
        return render_template(
            "message.html", title="Reset blocked", message="Type RESET exactly to clear the scan catalog."
        ), 400
    try:
        result = curator.reset_catalog()
    except Exception as exc:
        return render_template("message.html", title="Reset blocked", message=str(exc)), 400
    return render_template(
        "message.html", title="Catalog cleared",
        message=(f"Removed {result['files']} recovery records, {result['directories']} directory evidence records, "
                 f"{result['reference_files']} cached reference records, "
                 f"and {result['reports']} generated reports. No library files were changed. "
                 "The active saved scan is now blank; other saved scans were not changed."),
    )


@app.get("/preview/<int:file_id>")
def preview(file_id: int):
    try:
        path = curator.ensure_media_preview(file_id)
    except (FileNotFoundError, ValueError):
        abort(404)
    return send_file(path, conditional=True, max_age=3600)


@app.get("/reconstruction")
def reconstruction():
    requested_step = request.args.get("step", "").strip()
    folder_query = request.args.get("folder_q", "").strip()
    proposal_query = request.args.get("proposal_q", "").strip()
    review_state = request.args.get("review_state", "").strip() or None
    proposal_status = request.args.get("status", "").strip() or None
    basis = request.args.get("basis", "").strip() or None
    ai_settings = curator.ai_provider_settings()
    reconstruction_summary = curator.reconstruction_summary()
    attention = curator.reconstruction_attention_counts()
    ai_runs = curator.recent_ai_runs(limit=8)
    latest_structure = next(
        (run for run in ai_runs if run.get("request_kind") == "structure_analysis"), None,
    )

    if not reconstruction_summary.get("proposals"):
        recommended_step = "baseline"
    elif attention.get("structure_suggestions") or attention.get("review_questions"):
        recommended_step = "review"
    elif ai_settings.get("enabled") and (
        not latest_structure or latest_structure.get("status") == "failed"
    ):
        recommended_step = "ai"
    elif not reconstruction_summary.get("reviewed_folders") and not reconstruction_summary.get("context_items"):
        recommended_step = "evidence"
    elif reconstruction_summary.get("pending_proposals"):
        recommended_step = "review"
    elif reconstruction_summary.get("accepted_proposals"):
        recommended_step = "export"
    else:
        recommended_step = "evidence"
    active_step = requested_step if requested_step in {"baseline", "evidence", "ai", "review", "export"} else recommended_step
    proposal_page = max(1, request.args.get("proposal_page", 1, type=int))
    proposal_page_size = 50
    proposal_rows = []
    if active_step == "review":
        proposal_rows = curator.list_reconstruction_proposals(
            limit=proposal_page_size + 1, query=proposal_query or None,
            review_state=review_state, status=proposal_status, basis=basis,
            offset=(proposal_page - 1) * proposal_page_size,
        )
    export_preview = (
        curator.reconstruction_export_preview()
        if active_step == "export"
        else {
            "accepted": reconstruction_summary.get("accepted_proposals", 0), "directories": 0,
            "ready": 0, "collisions": 0, "blocked": 0, "unavailable": 0,
            "bytes_human": "—", "authorized": False, "token": "",
        }
    )
    return render_template(
        "reconstruction.html", allow_actions=curator.allow_actions, status=curator.status(),
        reconstruction=reconstruction_summary, attention=attention,
        active_step=active_step, recommended_step=recommended_step,
        folders=(curator.list_folder_context(query=folder_query or None, limit=100)
                 if active_step == "evidence" else []), folder_query=folder_query,
        context_items=(curator.list_recovery_context() if active_step == "evidence" else []),
        review_questions=(curator.list_review_questions(limit=20) if active_step == "review" else []),
        proposals=proposal_rows[:proposal_page_size], proposal_page=proposal_page,
        proposal_has_next=len(proposal_rows) > proposal_page_size,
        proposal_query=proposal_query, selected_review_state=review_state or "",
        selected_status=proposal_status or "", selected_basis=basis or "",
        proposal_options=(curator.proposal_filter_options() if active_step == "review" else {"statuses": [], "bases": []}),
        proposal_tree=[],
        directory_proposals=(curator.list_reconstruction_directories(limit=50) if active_step == "review" else []),
        export_preview=export_preview,
        ai_settings=ai_settings, ai_runs=ai_runs, latest_structure=latest_structure,
        ai_work_package=(curator.ai_work_package_status() if active_step in {"ai", "review"} else None),
        ai_candidate_count=reconstruction_summary.get("ai_pending", 0),
        structure_suggestions=(curator.list_structure_suggestions(limit=100)
                               if active_step in {"ai", "review"} else []),
    )


@app.get("/curate")
def curate():
    preview = curator.sanitization_overview()
    return render_template(
        "curate.html", status=curator.status(), summary=curator.summary(),
        preview=preview, allow_actions=curator.allow_actions,
        ai_settings=curator.ai_provider_settings(),
        conversation=curator.curation_conversation(),
    )


@app.post("/api/curate/analyze")
def api_start_sanitization_analysis():
    try:
        if not curator.start_sanitization_analysis():
            raise RuntimeError("Another scan or analysis job is already running.")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 409
    return jsonify({"ok": True, "status": curator.status()})


@app.post("/curate/preview")
def preview_sanitized_library():
    try:
        curator.sanitization_preview(authorize=True)
    except Exception as exc:
        return render_template(
            "message.html", title="Preview not created", message=str(exc),
        ), 400
    return redirect(url_for("curate") + "#build-library")


@app.post("/curate/build")
def build_sanitized_library():
    if request.form.get("confirmation", "").strip() != "CURATE":
        return render_template(
            "message.html", title="Build not started", message="Type CURATE exactly to confirm.",
        ), 400
    try:
        result = curator.export_sanitized_library(
            request.form.get("token", ""), request.form.get("allow_copy_fallback") == "1",
        )
    except Exception as exc:
        return render_template(
            "message.html", title="Review library not built", message=str(exc),
        ), 400
    return render_template(
        "message.html", title="Review library built",
        message=(
            f"Created {result['hardlinked']:,} hardlinks, {result['reflinked']:,} reflink clones, "
            f"and {result['copied']:,} full copies while preserving the source folders "
            f"({result['directories_created']:,} newly created). Applied {result['repaired']:,} metadata "
            f"repairs; {result['repair_failed']:,} repairs and {result['failed']:,} exports failed. "
            f"Included manifest: {result['manifest']}. Omitted manifest: {result['exclusions_manifest']}"
        ),
    )


@app.post("/api/curate/assistant/message")
def api_curation_assistant_message():
    values = request.get_json(silent=True) or {}
    try:
        conversation = curator.send_curation_message(str(values.get("message") or ""))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "conversation": conversation})


@app.post("/api/curate/assistant/proposal/<int:proposal_id>")
def api_review_curation_proposal(proposal_id: int):
    values = request.get_json(silent=True) or {}
    try:
        result = curator.review_curation_proposal(proposal_id, str(values.get("decision") or ""))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "result": result})


@app.post("/reconstruction/start")
def start_reconstruction():
    curator.start_reconstruction()
    return redirect(url_for("reconstruction"))


@app.post("/reconstruction/refresh")
def refresh_reconstruction():
    curator.start_reconstruction_plan_refresh()
    return redirect(url_for("reconstruction"))


@app.post("/folders/review")
def review_folder():
    try:
        curator.review_folder_context(
            int(request.form.get("directory_id", "0")), request.form.get("review_status", "unreviewed"),
            request.form.get("user_label", ""), request.form.get("notes", ""),
        )
    except Exception as exc:
        return render_template("message.html", title="Folder context not saved", message=str(exc)), 400
    return redirect(request.referrer or url_for("reconstruction"))


@app.post("/context/add")
def add_context():
    try:
        curator.add_recovery_context(
            request.form.get("context_type", "general"), request.form.get("label", ""),
            request.form.get("details", ""), request.form.get("match_text", ""),
            request.form.get("destination", ""),
        )
    except Exception as exc:
        return render_template("message.html", title="Recovery context not saved", message=str(exc)), 400
    return redirect(url_for("reconstruction", step="evidence") + "#recovery-context")


@app.post("/context/<int:context_id>/delete")
def delete_context(context_id: int):
    try:
        curator.delete_recovery_context(context_id)
    except Exception as exc:
        return render_template("message.html", title="Context clue not removed", message=str(exc)), 400
    return redirect(url_for("reconstruction", step="evidence") + "#recovery-context")


@app.post("/reconstruction/proposal/<int:file_id>")
def review_reconstruction_proposal(file_id: int):
    try:
        curator.review_reconstruction_proposal(
            file_id, request.form.get("review_state", "pending"),
            request.form.get("user_path", ""), request.form.get("note", ""),
        )
    except Exception as exc:
        return render_template("message.html", title="Proposal not updated", message=str(exc)), 400
    return redirect(request.referrer or url_for("reconstruction"))


@app.post("/reconstruction/proposals/accept-safe")
def accept_safe_reconstruction_proposals():
    try:
        changed = curator.bulk_accept_reconstruction(request.form.get("minimum_confidence", "85"))
    except Exception as exc:
        return render_template("message.html", title="Proposals not accepted", message=str(exc)), 400
    return render_template(
        "message.html", title="Safe proposals accepted",
        message=f"Accepted {changed:,} pending proposals. Generate a fresh dry run before export.",
    )


@app.post("/reconstruction/export/preview")
def preview_reconstruction_export():
    curator.reconstruction_export_preview(authorize=True)
    return redirect(url_for("reconstruction", step="export") + "#export-plan")


@app.post("/reconstruction/export")
def export_reconstruction():
    if request.form.get("confirmation") != "EXPORT":
        return render_template(
            "message.html", title="Export blocked", message="Type EXPORT exactly to confirm the accepted plan."
        ), 400
    try:
        result = curator.export_reconstruction(request.form.get("token", ""))
    except Exception as exc:
        return render_template("message.html", title="Export blocked", message=str(exc)), 400
    return render_template(
        "message.html", title="Accepted reconstruction exported",
        message=(f"Exported {result['exported']:,} files; {result['skipped']:,} skipped; "
                 f"{result['failed']:,} failed. The recovered source was not modified."),
    )


@app.post("/questions/answer")
def answer_question():
    try:
        curator.answer_review_question(
            int(request.form.get("question_id", "0")), request.form.get("answer", ""),
            request.form.get("dismiss") == "1",
        )
    except Exception as exc:
        return render_template("message.html", title="Answer not saved", message=str(exc)), 400
    return redirect(url_for("reconstruction", step="review") + "#review-questions")


@app.post("/facet/<int:file_id>")
def set_facet(file_id: int):
    try:
        curator.set_file_facet(
            file_id, request.form.get("facet_type", "topic"), request.form.get("value", ""),
            request.form.get("reason", ""),
        )
    except Exception as exc:
        return render_template("message.html", title="Classification not saved", message=str(exc)), 400
    return redirect(request.referrer or url_for("files"))


@app.post("/ai/provider")
def save_ai_provider():
    try:
        curator.save_ai_provider_settings({
            "provider_id": request.form.get("provider_id", "custom"),
            "provider_name": request.form.get("provider_name", "Local AI"),
            "endpoint": request.form.get("endpoint", ""),
            "model": request.form.get("model", ""),
            "api_key": request.form.get("api_key", ""),
            "api_key_env": request.form.get("api_key_env", ""),
            "clear_api_key": request.form.get("clear_api_key") == "1",
            "enabled": request.form.get("enabled") == "1",
            "allow_cloud_media": request.form.get("allow_cloud_media") == "1",
            "allow_sensitive_media": request.form.get("allow_sensitive_media") == "1",
        })
    except Exception as exc:
        return render_template("message.html", title="AI provider not saved", message=str(exc)), 400
    return redirect(url_for("reconstruction", step="ai") + "#ai-provider")


@app.post("/api/ai/provider/save")
def api_save_ai_provider():
    values = request.get_json(silent=True) or {}
    try:
        settings = curator.save_ai_provider_settings(values)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "settings": settings})


@app.post("/api/ai/provider/test")
def api_test_ai_provider():
    values = request.get_json(silent=True) or {}
    try:
        result = curator.test_ai_provider(values)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify(result)


@app.post("/ai/test")
def test_ai_provider():
    try:
        result = curator.test_ai_provider()
        models = ", ".join(result.get("models", [])[:10]) or "provider returned no model list"
        message = f"Connection succeeded. Endpoint is {'local/private' if result.get('local') else 'remote/public'}. Models: {models}"
    except Exception as exc:
        return render_template("message.html", title="AI connection failed", message=str(exc)), 400
    return render_template("message.html", title="AI connection succeeded", message=message)


@app.post("/ai/batch")
def start_ai_batch():
    try:
        curator.start_ai_batch(
            request.form.get("media_kind", "all"),
            request.form.get("pending_only") == "1",
            request.form.get("uncertain_only") == "1",
            int(request.form.get("limit", "100")),
        )
    except Exception as exc:
        return render_template("message.html", title="AI batch not started", message=str(exc)), 400
    return redirect(url_for("reconstruction", step="ai") + "#ai-batch")


@app.post("/ai/structure")
def start_ai_structure():
    try:
        curator.start_structure_ai(int(request.form.get("limit", "12")))
    except Exception as exc:
        return render_template("message.html", title="Folder interpretation not started", message=str(exc)), 400
    return redirect(url_for("reconstruction", step="ai") + "#ai-structure")


@app.post("/ai/structure/<int:suggestion_id>")
def review_ai_structure(suggestion_id: int):
    try:
        accepted = curator.review_structure_suggestion(
            suggestion_id, request.form.get("decision", "rejected")
        )
        if accepted:
            curator.start_reconstruction_plan_refresh()
    except Exception as exc:
        return render_template("message.html", title="AI suggestion not updated", message=str(exc)), 400
    return redirect(url_for("reconstruction", step="review") + "#ai-structure")


@app.post("/ai/analyze/<int:file_id>")
def analyze_with_ai(file_id: int):
    try:
        result = curator.analyze_file_with_ai(file_id)
    except Exception as exc:
        return render_template("message.html", title="AI analysis failed", message=str(exc)), 400
    questions = result.get("questions") if isinstance(result.get("questions"), list) else []
    message = str(result.get("caption") or "Analysis completed.")
    if questions:
        message += " Questions for review: " + " | ".join(str(item) for item in questions[:5])
    return render_template("message.html", title="AI analysis saved as suggestions", message=message)


@app.post("/decision/<int:file_id>")
def decision(file_id: int):
    curator.decide(file_id, request.form.get("decision", "undecided"))
    return redirect(request.referrer or url_for("index"))


@app.post("/category/<int:file_id>")
def category(file_id: int):
    curator.set_category(file_id, request.form.get("category", "Uncategorized"))
    return redirect(request.referrer or url_for("files"))


@app.post("/auto-decide-exact")
def auto_decide_exact():
    curator.auto_decide_exact()
    return redirect(url_for("groups", kind="exact"))


@app.post("/quarantine/<int:file_id>")
def quarantine(file_id: int):
    try:
        curator.quarantine_file(file_id)
    except Exception as exc:
        return render_template("message.html", title="Action blocked", message=str(exc)), 400
    return redirect(request.referrer or url_for("index"))


@app.post("/build-library")
def build_library():
    try:
        result = curator.build_curated_library()
    except Exception as exc:
        return render_template("message.html", title="Build blocked", message=str(exc)), 400
    return render_template(
        "message.html", title="Curated library built",
        message=(f"Exported {result['exported']} new files; {result['failed']} failed; "
                 f"{result['review_skipped']} files in undecided duplicate/similar groups were safely skipped. "
                 f"{result['known_good_skipped']} known-good matches were not copied. "
                 f"Catalog: {result['catalog']}"),
    )


@app.get("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8188, debug=False)
