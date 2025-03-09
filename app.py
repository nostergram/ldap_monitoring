import os
import time
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPException
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['DATABASE'] = 'users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

LDAP_SERVER = "ldap://localhost"
LDAP_BASE_DN = "dc=nick,dc=local"
LDAP_USER_DN = "uid={username},ou=users,dc=nick,dc=local"
ADMIN_USERNAME = "admin"

# Track active sessions (login queue)
active_users = set()
MAX_ACTIVE_USERS = 10

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Setup
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN,
                        rtt INTEGER,
                        ip_address TEXT,
                        failed_attempts INTEGER DEFAULT 0,
                        locked BOOLEAN DEFAULT 0)''')
        db.execute('''CREATE TABLE IF NOT EXISTS user_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        filename TEXT,
                        upload_time DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        db.commit()
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_ip = request.remote_addr
        db = get_db()

        # Check if account is locked
        locked = db.execute("SELECT locked FROM login_attempts WHERE username = ? ORDER BY timestamp DESC LIMIT 1", (username,)).fetchone()
        if locked and locked[0] == 1:
            flash('Account locked due to multiple failed login attempts. Contact admin.', 'danger')
            return redirect(url_for('login'))

        # Queue Handling
        if len(active_users) >= MAX_ACTIVE_USERS:
            flash('Login queue full. Please wait...', 'warning')
            return render_template('login.html')

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('login'))

        user_dn = LDAP_USER_DN.format(username=username)
        server = Server(LDAP_SERVER, get_info=ALL)

        try:
            start_time = time.time()
            conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            end_time = time.time()
            rtt = round((end_time - start_time) * 1000, 2)

            # Get last known IP
            last_login = db.execute("SELECT ip_address FROM login_attempts WHERE username = ? ORDER BY timestamp DESC LIMIT 1", (username,)).fetchone()
            ip_changed = last_login and last_login[0] != user_ip

            # Reset failed attempts on successful login
            db.execute("INSERT INTO login_attempts (username, success, rtt, ip_address, failed_attempts, locked) VALUES (?, ?, ?, ?, 0, 0)",
                       (username, True, rtt, user_ip))
            db.commit()

            session['username'] = username
            active_users.add(username)

            if ip_changed:
                flash(f'Alert: New login from IP {user_ip}!', 'danger')

            flash(f'Login successful! RTT: {rtt}ms', 'success')

            return redirect(url_for('admin_dashboard') if username == ADMIN_USERNAME else url_for('user_dashboard'))

        except LDAPException:
            failed_attempts = db.execute("SELECT failed_attempts FROM login_attempts WHERE username = ? ORDER BY timestamp DESC LIMIT 1",
                                         (username,)).fetchone()
            failed_attempts = failed_attempts[0] + 1 if failed_attempts else 1

            # Lock account if 5 failed attempts
            lock_status = 1 if failed_attempts >= 5 else 0

            db.execute("INSERT INTO login_attempts (username, success, failed_attempts, ip_address, locked) VALUES (?, ?, ?, ?, ?)",
                       (username, False, failed_attempts, user_ip, lock_status))
            db.commit()

            if failed_attempts >= 5:
                flash(f'Account locked due to multiple failed login attempts!', 'danger')

            flash(f'Login failed! Attempt {failed_attempts}/5', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'username' not in session or session['username'] == ADMIN_USERNAME:
        return redirect(url_for('login'))

    db = get_db()

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            db.execute("INSERT INTO user_files (username, filename) VALUES (?, ?)", (session['username'], filename))
            db.commit()
            flash('File uploaded successfully!', 'success')

    files = db.execute("SELECT filename, upload_time FROM user_files WHERE username = ?", (session['username'],)).fetchall()
    return render_template('user_dashboard.html', username=session['username'], files=files)

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'username' not in session or session['username'] != ADMIN_USERNAME:
        return redirect(url_for('login'))

    db = get_db()

    if request.method == 'POST':
        username = request.form['username']
        db.execute("UPDATE login_attempts SET locked = 0, failed_attempts = 0 WHERE username = ?", (username,))
        db.commit()
        flash(f'Account {username} has been unlocked.', 'success')

    logins = db.execute("SELECT username, timestamp, success, rtt, ip_address, failed_attempts, locked FROM login_attempts ORDER BY timestamp DESC").fetchall()
    return render_template('admin_dashboard.html', username=session['username'], logins=logins)

@app.route('/logout')
def logout():
    active_users.discard(session.get('username'))
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)