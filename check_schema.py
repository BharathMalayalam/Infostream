import sqlite3
conn = sqlite3.connect('notifications.db')
cur = conn.cursor()
cur.execute("PRAGMA table_info(users)")
print([row[1] for row in cur.fetchall()])
conn.close()
