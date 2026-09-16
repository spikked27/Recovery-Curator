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
    return render_template(
        "files.html", files=curator.list_files(category, validation, known_good), category=category,
        validation=validation, known_good=known_good, summary=curator.summary(),
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
        message=(f"Removed {result['files']} recovery records, {result['reference_files']} cached reference records, "
                 f"and {result['reports']} generated reports. No library files were changed. "
                 "The active saved scan is now blank; other saved scans were not changed."),
    )


@app.get("/preview/<int:file_id>")
def preview(file_id: int):
    row = curator.get_file(file_id)
    if not row or not row["is_image"]:
        abort(404)
    path = Path(row["path"])
    if not path.exists():
        abort(404)
    return send_file(path, conditional=True, max_age=3600)


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
