from __future__ import annotations

import json
import time
import tempfile
import uuid
from pathlib import Path
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from io import BytesIO
from werkzeug.utils import secure_filename

import db_manager
from main import analyze

app = Flask(__name__)
CORS(app)


@app.errorhandler(Exception)
def on_error(exc):
    return jsonify({"error": str(exc), "code": 500}), 500


@app.post('/api/analyze')
def api_analyze():
    start = time.perf_counter()
    text = request.form.get('text', '')
    files = request.files.getlist('files')
    results = []
    if text:
        results.append(analyze(text))
    for f in files:
        safe_name = secure_filename(Path(f.filename or '').name)
        if not safe_name:
            safe_name = 'upload.bin'
        path = str(Path(tempfile.gettempdir()) / safe_name)
        f.save(path)
        results.append(analyze(path))
    if not results:
        merged = analyze('')
    elif len(results) == 1:
        merged = results[0]
    else:
        session_id = str(uuid.uuid4())
        merged = {
            "session_id": session_id,
            "created_at": results[0].get("created_at"),
            "iocs": [ioc for result in results for ioc in result.get("iocs", [])],
            "stats": results[-1].get("stats", {}),
        }
        sp = db_manager.DB_ROOT / "raw/sessions" / f"{session_id}.json"
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps(merged, indent=2))
    merged['duration_ms'] = int((time.perf_counter() - start) * 1000)
    return jsonify(merged)


@app.get('/api/session/<session_id>')
def api_session(session_id): return jsonify(db_manager.get_session(session_id))


@app.get('/api/stats')
def api_stats(): return jsonify(db_manager.get_stats())


@app.get('/api/search')
def api_search():
    q = request.args.get('q', '')
    return jsonify({"match": db_manager.search_ioc(q), "history": db_manager.get_history(q)})


@app.get('/api/export/<session_id>')
def api_export(session_id):
    fmt = request.args.get('format', 'json')
    data = db_manager.export_report(session_id, fmt)
    mime = {'json': 'application/json', 'csv': 'text/csv', 'pdf': 'application/pdf'}.get(fmt, 'application/octet-stream')
    return send_file(BytesIO(data), mimetype=mime, as_attachment=True, download_name=f"netintel_{session_id}.{fmt}")


@app.get('/api/history/<path:encoded_value>')
def api_history(encoded_value): return jsonify(db_manager.get_history(encoded_value))


@app.delete('/api/session/<session_id>')
def api_delete(session_id):
    p = db_manager.DB_ROOT / 'raw/sessions' / f'{session_id}.json'
    if p.exists(): p.unlink()
    return jsonify({"deleted": True})


@app.get('/api/health')
def api_health(): return jsonify({"status": "ok", "db_stats": db_manager.get_stats()})


if __name__ == '__main__':
    app.run(debug=True)
