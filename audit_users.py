import sqlite3
conn = sqlite3.connect('notifications.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT username, role, phone FROM users")
for row in cur.fetchall():
    print(dict(row))
conn.close()
