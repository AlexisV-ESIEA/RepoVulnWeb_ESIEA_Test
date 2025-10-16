from flask import Flask, request, render_template, send_from_directory, abort
import sqlite3
import os
import werkzeug.utils
import uuid
import ipaddress
import subprocess
import platform

app = Flask(__name__)

# dossiers
UPLOAD_FOLDER = "uploads"
CTF_FOLDER = os.path.join(UPLOAD_FOLDER, "ctf_files")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CTF_FOLDER, exist_ok=True)

# base de donnée sqlit3
def get_db():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn

# /
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

# /search
@app.route("/search", methods=["POST"])
def search():
    q = request.form.get("q", "")
    conn = get_db()
    sql = "SELECT id, name, comment FROM users WHERE name LIKE '%{}%'".format(q)
    cur = conn.execute(sql)
    rows = cur.fetchall()
    return render_template("index.html", results=rows, query=q)

# /upload
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

# Liste des uploads
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

# DL file
@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    safe_filename = werkzeug.utils.secure_filename(filename)
    full_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    if not os.path.exists(full_path):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, safe_filename, as_attachment=True)

# naviguer dans /uploads
@app.route("/files", methods=["GET"])
def list_files():
    
    base_dir = os.path.abspath(UPLOAD_FOLDER)
    subpath = request.args.get("path", "").strip()
    requested = os.path.normpath(os.path.join(base_dir, subpath))

    # bloquer a /upload
    if not (requested == base_dir or requested.startswith(base_dir + os.sep)):
        return "<h3>Accès refusé</h3>", 403

    if not os.path.exists(requested):
        return "<h3>Ce fichier ou dossier n'existe pas.</h3>", 404

    # si fichier = telecharge
    if os.path.isfile(requested):
        directory = os.path.dirname(requested)
        filename = os.path.basename(requested)
        return send_from_directory(directory, filename, as_attachment=True)

    # sinon affiche contenu 
    entries = sorted(os.listdir(requested), key=lambda s: s.lower())
    relpath = os.path.relpath(requested, base_dir)
    display_rel = "" if relpath == "." else relpath
    html = f"<h2>Contenu de /{display_rel}</h2><ul>"

    for e in entries:
        full_rel = os.path.join(display_rel, e) if display_rel else e
        full_abs = os.path.join(requested, e)
        if os.path.isdir(full_abs):
            html += f'<li>📁 <a href="/files?path={full_rel}">{e}/</a></li>'
        else:
            html += f'<li>📄 <a href="/files?path={full_rel}">{e}</a> - <small>{os.path.getsize(full_abs)} bytes</small></li>'
    html += "</ul>"

    # /
    if relpath != ".":
        parent = os.path.dirname(relpath)
        html += f'<p><a href="/files?path={parent}">⬅️ Retour</a></p>'
    html += '<p><a href="/">🏠 Accueil</a></p>'
    return html


def safe_join_and_check(base_dir, filename):
    safe_name = werkzeug.utils.secure_filename(filename)
    target = os.path.normpath(os.path.join(base_dir, safe_name))
    base_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(target)
    if not (target_real == base_real or target_real.startswith(base_real + os.sep)):
        return None
    return target_real

# interface du /ctf
@app.route("/ctf", methods=["GET", "POST"])
def ctf():
    result = ""
    error = ""
    if request.method == "POST":
        cmd = (request.form.get("cmd") or "").strip()
        if not cmd:
            error = "No command provided"
        else:
            parts = cmd.split()
            verb = parts[0].lower()
            if verb == "ls":
                try:
                    items = os.listdir(CTF_FOLDER)
                    result = "\n".join(items) if items else "(empty)"
                except Exception as e:
                    error = f"Error listing: {e}"
            elif verb == "cat":
                if len(parts) < 2:
                    error = "Usage: cat <filename>"
                else:
                    fname = " ".join(parts[1:])
                    target = safe_join_and_check(CTF_FOLDER, fname)
                    if not target or not os.path.isfile(target):
                        error = "File not found or invalid"
                    else:
                        try:
                            with open(target, "rb") as fh:
                                data = fh.read(4096)  # 4 KiB max
                            result = data.decode("utf-8", errors="replace")
                            if os.path.getsize(target) > 4096:
                                result += "\n... (truncated)"
                        except Exception as e:
                            error = f"Error reading file: {e}"
            elif verb == "ping":
                if len(parts) != 2:
                    error = "Usage: ping <ipv4>"
                else:
                    ip = parts[1]
                    try:
                        addr = ipaddress.ip_address(ip)
                        if addr.version != 4:
                            error = "Only IPv4 allowed"
                        else:
                            # build command list (no shell)
                            if platform.system().lower().startswith("win"):
                                cmd_list = ["ping", "-n", "1", ip]
                            else:
                                cmd_list = ["ping", "-c", "1", ip]
                            try:
                                proc = subprocess.run(
                                    cmd_list,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=4,
                                    text=True,
                                )
                                result = (proc.stdout or "") + (proc.stderr or "")
                            except subprocess.TimeoutExpired:
                                error = "Ping timed out"
                            except Exception as e:
                                error = f"Error executing ping: {e}"
                    except ValueError:
                        error = "Invalid IP address"
            else:
                error = "Command not allowed. Allowed: ls, cat <filename>, ping <ipv4>"

    return render_template("ctf.html", result=result, error=error, ctf_dir=CTF_FOLDER)

#Lancement appli
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)