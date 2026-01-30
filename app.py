# app.py
# Department-Based Student Notification System (Pure SQLite)

import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DB_NAME = 'notifications.db'

# ======================
# Database Helpers
# ======================
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# ======================
# Initialize Database
# ======================
def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT,
            year TEXT,
            phone TEXT
        )
    ''')
    
    # Migration for missing columns
    try:
        cur.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    except sqlite3.OperationalError:
        pass # Column already exists

    cur.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            department TEXT,
            year TEXT,
            is_urgent INTEGER DEFAULT 0,
            category TEXT,
            created_at TEXT
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS placements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT NOT NULL,
            role TEXT NOT NULL,
            eligibility TEXT,
            deadline TEXT,
            description TEXT,
            is_urgent INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Placement',
            created_at TEXT
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS exams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exam_type TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            department TEXT,
            year TEXT,
            is_urgent INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Exam Cell',
            created_at TEXT
        )
    ''')

    conn.commit()
    conn.close()

# ======================
# Auth Decorator
# ======================
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role:
                # Support single role or list of roles
                allowed_roles = [role] if isinstance(role, str) else role
                if session.get('role') not in allowed_roles:
                    flash('Unauthorized access')
                    return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ======================
# Routes
# ======================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        department = request.form.get('department')
        year = request.form.get('year')
        phone = request.form.get('phone')

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO users (username, password, role, department, year, phone)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password, role, department, year, phone))
            conn.commit()
        except sqlite3.IntegrityError:
            flash('Username already exists')
            return redirect(url_for('register'))
        finally:
            conn.close()

        flash('Registration successful')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        selected_role = request.form.get('role', 'student')

        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username=?', (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            if user['role'] != selected_role:
                flash(f'Identity verification failed: Selected role does not match user profile.')
                return render_template('login.html')

            session['user_id'] = user['id']
            session['role'] = user['role']
            session['department'] = user['department']
            session['year'] = user['year']

            if user['role'] in ['admin', 'staff']:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Access Denied: Invalid credentials')

    return render_template('login.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required(role=['admin', 'staff'])
def admin_dashboard():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        notif_type = request.form['type']

        departments = None
        years = None
        if notif_type == 'department':
            # Handle multi-select from form
            departments = ','.join(request.form.getlist('department'))
            years = ','.join(request.form.getlist('year'))

        is_urgent = 1 if request.form.get('is_urgent') else 0
        category = request.form.get('category', 'Events')

        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO notifications (title, content, department, year, is_urgent, category, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (title, content, departments, years, is_urgent, category, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()

        flash('Notification published')

    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM notifications ORDER BY created_at DESC')
    notifications = cur.fetchall()
    cur.execute('SELECT * FROM placements ORDER BY created_at DESC')
    placements = cur.fetchall()
    cur.execute('SELECT * FROM exams ORDER BY created_at DESC')
    exams = cur.fetchall()

    users = []
    if session.get('role') == 'admin':
        cur.execute('SELECT * FROM users ORDER BY role DESC, username ASC')
        users = cur.fetchall()

    conn.close()

    return render_template('admin_dashboard.html', notifications=notifications, placements=placements, exams=exams, users=users)

@app.route('/admin/add_staff', methods=['POST'])
@login_required(role='admin')
def add_staff():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    phone = request.form.get('phone')
    
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('''
            INSERT INTO users (username, password, role, phone)
            VALUES (?, ?, 'staff', ?)
        ''', (username, password, phone))
        conn.commit()
        flash(f'Staff account created for {username}')
    except sqlite3.IntegrityError:
        flash('Username already exists')
    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_student', methods=['POST'])
@login_required(role='admin')
def add_student():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    department = request.form['department']
    year = request.form['year']
    phone = request.form.get('phone')
    
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('''
            INSERT INTO users (username, password, role, department, year, phone)
            VALUES (?, ?, 'student', ?, ?, ?)
        ''', (username, password, department, year, phone))
        conn.commit()
        flash(f'Student identity provisioned: {username}')
    except sqlite3.IntegrityError:
        flash('Identifier already exists in network')
    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required(role='admin')
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('Cannot revoke own identity')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE id = ? AND role != "admin"', (user_id,))
    conn.commit()
    conn.close()
    
    flash('Identity revoked and access terminated')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/placement', methods=['POST'])
@login_required(role=['admin', 'staff'])
def admin_placement():
    company = request.form['company']
    role = request.form['role']
    eligibility = request.form['eligibility']
    deadline = request.form['deadline']
    description = request.form['description']

    is_urgent = 1 if request.form.get('is_urgent') else 0
    category = 'Placement'

    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO placements (company, role, eligibility, deadline, description, is_urgent, category, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (company, role, eligibility, deadline, description, is_urgent, category, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()

    flash('Placement update broadcasting...')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/exam', methods=['POST'])
@login_required(role=['admin', 'staff'])
def admin_exam():
    exam_type = request.form['exam_type']
    title = request.form['title']
    content = request.form['content']
    departments = ','.join(request.form.getlist('department'))
    years = ','.join(request.form.getlist('year'))

    is_urgent = 1 if request.form.get('is_urgent') else 0
    category = 'Exam Cell'

    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO exams (exam_type, title, content, department, year, is_urgent, category, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (exam_type, title, content, departments, years, is_urgent, category, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()

    flash('Exam update published')

    return redirect(url_for('admin_dashboard'))

@app.route('/student')
@login_required(role='student')
def student_dashboard():
    dept = session.get('department')
    year = session.get('year')

    conn = get_db()
    cur = conn.cursor()
    
    # Fetch Notifications
    cur.execute('''
        SELECT 'notification' as type, * FROM notifications
        WHERE department IS NULL OR department = ''
        OR (',' || department || ',' LIKE '%,' || ? || ',%' AND ',' || year || ',' LIKE '%,' || ? || ',%')
    ''', (dept, year))
    notifications = [dict(row) for row in cur.fetchall()]

    # Fetch Placements (assuming all students see all placements for now, or add filtering if needed)
    cur.execute("SELECT 'placement' as type, * FROM placements")
    placements = [dict(row) for row in cur.fetchall()]

    # Fetch Exams
    cur.execute('''
        SELECT 'exam' as type, * FROM exams
        WHERE department IS NULL OR department = ''
        OR (',' || department || ',' LIKE '%,' || ? || ',%' AND ',' || year || ',' LIKE '%,' || ? || ',%')
    ''', (dept, year))
    exams = [dict(row) for row in cur.fetchall()]
    
    conn.close()

    # Combine all streams
    all_streams = notifications + placements + exams
    
    # Sort by is_urgent (DESC) then created_at (DESC)
    all_streams.sort(key=lambda x: (x.get('is_urgent', 0), x.get('created_at', '')), reverse=True)

    return render_template('student_dashboard.html', streams=all_streams)

@app.route('/api/urgent_check')
@login_required(role='student')
def urgent_check():
    dept = session.get('department')
    year = session.get('year')
    time_limit = request.args.get('since', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    conn = get_db()
    cur = conn.cursor()
    
    # Check Notifications
    cur.execute('''
        SELECT 'notification' as type, title, content, created_at FROM notifications
        WHERE is_urgent = 1 AND created_at > ?
        AND (department IS NULL OR department = ''
        OR (',' || department || ',' LIKE '%,' || ? || ',%' AND ',' || year || ',' LIKE '%,' || ? || ',%'))
    ''', (time_limit, dept, year))
    n = [dict(row) for row in cur.fetchall()]

    # Check Placements
    cur.execute('''
        SELECT 'placement' as type, company as title, role as content, created_at FROM placements
        WHERE is_urgent = 1 AND created_at > ?
    ''', (time_limit,))
    p = [dict(row) for row in cur.fetchall()]

    # Check Exams
    cur.execute('''
        SELECT 'exam' as type, title, exam_type as content, created_at FROM exams
        WHERE is_urgent = 1 AND created_at > ?
        AND (department IS NULL OR department = ''
        OR (',' || department || ',' LIKE '%,' || ? || ',%' AND ',' || year || ',' LIKE '%,' || ? || ',%'))
    ''', (time_limit, dept, year))
    e = [dict(row) for row in cur.fetchall()]
    
    conn.close()
    return {"urgent_alerts": n + p + e}

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ======================
# Run App
# ======================
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
