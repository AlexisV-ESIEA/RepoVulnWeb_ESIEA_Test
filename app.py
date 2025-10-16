from flask import Flask, request, render_template, redirect, url_for
import sqlite3
import os

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

# SQL injection
@app.route("/search", methods=["POST"])
def search():
    q = request.form.get("q", "")
    conn = get_db()
    # Vulnérabilité ici
    sql = "SELECT id, name, comment FROM users WHERE name LIKE '%{}%'".format(q)
    cur = conn.execute(sql)
    rows = cur.fetchall()
    return render_template("index.html", results=rows, query=q)

# upload de fichier
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return "No file", 400
    path = os.path.join(UPLOAD_FOLDER, f.filename)
    f.save(path)  # Sans validation on sauvegarde le fichier
    return "Uploaded: " + f.filename

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
