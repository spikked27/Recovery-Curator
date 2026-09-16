from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

from .curator import Curator, human_bytes


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


curator = Curator(
    source=Path(os.environ.get("SOURCE_ROOT", "/source")),
    output=Path(os.environ.get("OUTPUT_ROOT", "/output")),
    quarantine=Path(os.environ.get("QUARANTINE_ROOT", "/quarantine")),
    db_path=Path(os.environ.get("DATA_DIR", "/config")) / "catalog.sqlite3",
    allow_actions=env_bool("ALLOW_ACTIONS", False),
    analysis_workers=int(os.environ.get("ANALYSIS_WORKERS", "2")),
    hash_workers=int(os.environ.get("HASH_WORKERS", "2")),
    batch_size=int(os.environ.get("SCAN_BATCH_SIZE", "64")),
    similarity_radius=int(os.environ.get("SIMILARITY_DISTANCE", "6")),
)

app = Flask(__name__)
app.jinja_env.filters["human_bytes"] = human_bytes


@app.get("/")
def index():
    return render_template("index.html", summary=curator.summary(), status=curator.status())


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
    return jsonify({"status": curator.status(), "summary": curator.summary()})


@app.get("/groups/<kind>")
def groups(kind: str):
    if kind not in {"exact", "similar"}:
        abort(404)
    return render_template("groups.html", kind=kind, groups=curator.group_rows(kind), summary=curator.summary())


@app.get("/files")
def files():
    category = request.args.get("category") or None
    validation = request.args.get("validation") or None
    return render_template(
        "files.html", files=curator.list_files(category, validation), category=category,
        validation=validation, summary=curator.summary(),
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
                 f"Catalog: {result['catalog']}"),
    )


@app.get("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8188, debug=False)
