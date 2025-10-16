import sqlite3

conn = sqlite3.connect("app.db")
c = conn.cursor()
c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, comment TEXT)")
c.execute("DELETE FROM users")
c.executemany("INSERT INTO users (name, comment) VALUES (?, ?)", [
    ("alice", "hello"),
    ("bob", "I like cats"),
    ("admin", "superuser"),
])
conn.commit()
conn.close()
print("DB initialized")
