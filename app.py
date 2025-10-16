from flask import Flask, request, render_template, send_from_directory, abort
import sqlite3, os, werkzeug.utils, uuid

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

# Search (existing vuln intentionally left as exercise)
@app.route("/search", methods=["POST"])
def search():
    q = request.form.get("q", "")
    conn = get_db()
    sql = "SELECT id, name, comment FROM users WHERE name LIKE '%{}%'".format(q)
    cur = conn.execute(sql)
    rows = cur.fetchall()
    return render_template("index.html", results=rows, query=q)

# Secure upload: use secure_filename + UUID prefix
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return "No file", 400
    filename = werkzeug.utils.secure_filename(f.filename)
    if filename == "":
        return "Invalid filename", 400
    safe_name = f"{uuid.uuid4().hex}_{filename}"
    path = os.path.join(UPLOAD_FOLDER, safe_name)
    f.save(path)
    return f"Uploaded: {safe_name}"

# List uploaded files (simple HTML list with download links)
@app.route("/uploads_list", methods=["GET"])
def uploads_list():
    try:
        files = os.listdir(UPLOAD_FOLDER)
    except FileNotFoundError:
        files = []
    html = "<h1>Uploads</h1><ul>"
    for fn in files:
        safe_fn = werkzeug.utils.secure_filename(fn)
        html += f'<li>{safe_fn} - <a href="/download/{safe_fn}">download</a></li>'
    html += "</ul>"
    return html

# Download a specific uploaded file (prevents path traversal)
@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    safe_filename = werkzeug.utils.secure_filename(filename)
    full_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    if not os.path.exists(full_path):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, safe_filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)

