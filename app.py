import logging
from flask import Flask, request, jsonify, redirect, abort
import sqlite3
import re
import os

app = Flask(__name__)
DATABASE = './data/shortcode.db'

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

ALLOWED_IPS = os.getenv('ALLOWED_IPS', '127.0.0.1').split(',')

PUBLIC_ROUTES = [
    (r'^/[^/]+$', 'GET')
]

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS short_urls (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            key TEXT UNIQUE NOT NULL,
                            url TEXT NOT NULL
                        )''')

def is_valid_shortcode(key):
    return re.match(r'^[a-zA-Z0-9_-]+$', key) is not None

@app.before_request
def restrict_ips():
    remote_addr = request.headers.get('X-Forwarded-For', request.remote_addr)

    if remote_addr in ALLOWED_IPS:
        return

    for pattern, method in PUBLIC_ROUTES:
        if re.match(pattern, request.path) and request.method == method:
            return

    abort(403, description="Access denied")

@app.route('/', methods=['POST'])
def create_or_update_shortcode():
    data = request.json
    url = data.get('url')
    shortcode = data.get('shortcode')

    if not url or not shortcode:
        return jsonify({"error": "Both 'url' and 'shortcode' are required"}), 400

    if not is_valid_shortcode(shortcode):
        return jsonify({"error": "Invalid shortcode format"}), 400

    with sqlite3.connect(DATABASE) as conn:
        try:
            conn.execute('''
                INSERT INTO short_urls (key, url) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET url = excluded.url
            ''', (shortcode, url))
            conn.commit()
            return jsonify({"shortcode": shortcode, "url": url}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/', methods=['GET'])
def list_shortcodes():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT key, url FROM short_urls')
        records = [{"shortcode": row[0], "url": row[1]} for row in cur.fetchall()]
        return jsonify(records), 200

@app.route('/<key>', methods=['GET'])
def redirect_shortcode(key):
    if not is_valid_shortcode(key):
        abort(400, description="Invalid shortcode format")

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT url FROM short_urls WHERE key = ?', (key,))
        row = cur.fetchone()
        if row:
            return redirect(row[0])
        return jsonify({"error": "Shortcode not found"}), 404

@app.route('/<key>', methods=['DELETE'])
def delete_shortcode(key):
    if not is_valid_shortcode(key):
        abort(400, description="Invalid shortcode format")

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM short_urls WHERE key = ?', (key,))
        conn.commit()
        if cur.rowcount > 0:
            return jsonify({"message": f"Shortcode '{key}' deleted successfully"}), 200
        return jsonify({"error": "Shortcode not found"}), 404

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

