from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

from .curator import Curator, human_bytes
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
    return jsonify({
        "status": curator.status(), "summary": curator.summary(),
        "active_profile": profiles.active_profile(),
    })


@app.get("/scans")
def scans():
    return render_template(
        "scans.html", profiles=profiles.list_profiles(), active_profile=profiles.active_profile(),
        status=curator.status(), summary=curator.summary(),
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
    return render_template("groups.html", kind=kind, groups=curator.group_rows(kind), summary=curator.summary())


@app.get("/files")
def files():
    category = request.args.get("category") or None
    validation = request.args.get("validation") or None
    known_good_value = request.args.get("known_good")
    known_good = None if known_good_value is None else known_good_value == "1"
    media_kind = request.args.get("media_kind") or None
    return render_template(
        "files.html", files=curator.list_files(category, validation, known_good, media_kind), category=category,
        validation=validation, known_good=known_good, media_kind=media_kind, summary=curator.summary(),
    )


@app.get("/references")
def references():
    relative = request.args.get("path", ".")
    try:
        browser = curator.browse_reference_directories(relative)
    except Exception as exc:
        return render_template(
            "references.html", browser=None, error=str(exc), summary=curator.summary(),
        ), 400
    return render_template("references.html", browser=browser, error=None, summary=curator.summary())


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
    folder_query = request.args.get("folder_q", "").strip()
    proposal_query = request.args.get("proposal_q", "").strip()
    review_state = request.args.get("review_state", "").strip() or None
    proposal_status = request.args.get("status", "").strip() or None
    basis = request.args.get("basis", "").strip() or None
    ai_settings = curator.ai_provider_settings()
    return render_template(
        "reconstruction.html", summary=curator.summary(), status=curator.status(),
        reconstruction=curator.reconstruction_summary(),
        folders=curator.list_folder_context(query=folder_query or None), folder_query=folder_query,
        context_items=curator.list_recovery_context(),
        review_questions=curator.list_review_questions(),
        proposals=curator.list_reconstruction_proposals(
            query=proposal_query or None, review_state=review_state,
            status=proposal_status, basis=basis,
        ),
        proposal_query=proposal_query, selected_review_state=review_state or "",
        selected_status=proposal_status or "", selected_basis=basis or "",
        proposal_options=curator.proposal_filter_options(),
        proposal_tree=curator.reconstruction_tree(),
        directory_proposals=curator.list_reconstruction_directories(),
        export_preview=curator.reconstruction_export_preview(),
        ai_settings=ai_settings, ai_runs=curator.recent_ai_runs(),
        ai_candidate_count=curator.ai_batch_candidate_count(),
        structure_suggestions=curator.list_structure_suggestions(),
    )


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
    return redirect(url_for("reconstruction") + "#recovery-context")


@app.post("/context/<int:context_id>/delete")
def delete_context(context_id: int):
    try:
        curator.delete_recovery_context(context_id)
    except Exception as exc:
        return render_template("message.html", title="Context clue not removed", message=str(exc)), 400
    return redirect(url_for("reconstruction") + "#recovery-context")


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
    return redirect(url_for("reconstruction") + "#export-plan")


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
    return redirect(url_for("reconstruction") + "#review-questions")


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
            "provider_name": request.form.get("provider_name", "Local AI"),
            "endpoint": request.form.get("endpoint", ""),
            "model": request.form.get("model", ""),
            "api_key_env": request.form.get("api_key_env", ""),
            "enabled": request.form.get("enabled") == "1",
            "allow_cloud_media": request.form.get("allow_cloud_media") == "1",
            "allow_sensitive_media": request.form.get("allow_sensitive_media") == "1",
        })
    except Exception as exc:
        return render_template("message.html", title="AI provider not saved", message=str(exc)), 400
    return redirect(url_for("reconstruction") + "#ai-provider")


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
    return redirect(url_for("reconstruction") + "#ai-batch")


@app.post("/ai/structure")
def start_ai_structure():
    try:
        curator.start_structure_ai(int(request.form.get("limit", "300")))
    except Exception as exc:
        return render_template("message.html", title="Folder interpretation not started", message=str(exc)), 400
    return redirect(url_for("reconstruction") + "#ai-structure")


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
    return redirect(url_for("reconstruction") + "#ai-structure")


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
