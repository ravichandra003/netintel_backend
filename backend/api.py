from __future__ import annotations

import time
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from io import BytesIO

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
    iocs = []
    if text:
        iocs.append(analyze(text))
    for f in files:
        path = f"/tmp/{f.filename}"
        f.save(path)
        iocs.append(analyze(path))
    merged = iocs[-1] if iocs else analyze('')
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
