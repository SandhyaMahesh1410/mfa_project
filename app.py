from flask import Flask, render_template, request, redirect, session
import sqlite3
import pyotp
import qrcode
import os
import hashlib
from datetime import datetime, timedelta
import requests
from risk_engine import calculate_risk_score

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY"

# ================= DATABASE SETUP =====================
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        otp_secret TEXT,
        mfa_enabled INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        lock_until DATETIME
    )''')

    # Trusted devices table
    c.execute('''CREATE TABLE IF NOT EXISTS trusted_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        device_id TEXT,
        device_name TEXT,
        last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        failed_otp_attempts INTEGER DEFAULT 0,
        lock_until DATETIME
    )''')

    # Audit logs
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        action TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        location TEXT,
        device_id TEXT
    )''')

    conn.commit()
    conn.close()

init_db()

# ================== HELPERS ===========================
def get_user(email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    user = c.fetchone()
    conn.close()
    return user

def log_action(email, action, ip=None, location=None, device_id=None):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_log(email, action, ip, location, device_id) VALUES (?,?,?,?,?)",
        (email, action, ip, location, device_id)
    )
    conn.commit()
    conn.close()

def get_device_id():
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr
    raw = user_agent + str(ip)
    device_id = hashlib.sha256(raw.encode()).hexdigest()
    return device_id

def get_ip_location(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/").json()
        city = response.get("city", "")
        region = response.get("region", "")
        country = response.get("country_name", "")
        return f"{city}, {region}, {country}"
    except:
        return "Unknown"

# ================== ROUTES ============================
@app.route('/')
def home():
    return redirect('/login')

# ---------------- REGISTER -----------------------------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        secret = pyotp.random_base32()

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users(email, password, otp_secret) VALUES (?,?,?)",
                      (email, password, secret))
            conn.commit()
            log_action(email, "Registered")
            session['email'] = email
            return redirect('/setup_otp')
        except:
            return "User already exists"
        finally:
            conn.close()
    return render_template('register.html')

# ---------------- LOGIN -----------------------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user(email)
        if not user:
            return "No such user"

        stored_pass = user[2]
        failed_attempts = user[5]
        lock_until = user[6]

        # Check lock
        if lock_until:
            now = datetime.now()
            lock_time = datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S.%f")
            if now < lock_time:
                return f"Account locked until {lock_time}"

        # Wrong password
        if password != stored_pass:
            failed_attempts += 1
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            if failed_attempts >= 3:  # lock after 3 attempts
                lock_time = datetime.now() + timedelta(minutes=10)
                c.execute("UPDATE users SET failed_attempts=?, lock_until=? WHERE email=?",
                          (failed_attempts, lock_time, email))
                conn.commit()
                conn.close()
                log_action(email, "Account Locked due to 3 failed password attempts")
                return "Too many wrong passwords! Account locked for 10 minutes."
            else:
                c.execute("UPDATE users SET failed_attempts=? WHERE email=?", (failed_attempts, email))
                conn.commit()
                conn.close()
                log_action(email, "Failed Login Attempt")
                return f"Incorrect password ({failed_attempts}/3 attempts)"

        # Reset failed attempts
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("UPDATE users SET failed_attempts=0, lock_until=NULL WHERE email=?", (email,))
        conn.commit()
        conn.close()

        # Device & IP
        device_id = get_device_id()
        ip = request.remote_addr
        location = get_ip_location(ip)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM trusted_devices WHERE email=? AND device_id=?", (email, device_id))
        trusted = c.fetchone()
        conn.close()

        session['email'] = email
        session['device_id'] = device_id
        session['ip'] = ip
        session['location'] = location

        # Risk Score
        risk = calculate_risk_score(request)  # you can improve logic later
        if risk >= 50 or not trusted:
            log_action(email, "OTP Required due to risk/new device", ip, location, device_id)
            return redirect('/verify_otp_login')
        else:
            log_action(email, "Login Success from known device", ip, location, device_id)
            return redirect('/dashboard')

    return render_template('login.html')

# ---------------- SETUP OTP -----------------------------
@app.route('/setup_otp')
def setup_otp():
    if 'email' not in session:
        return redirect('/login')
    email = session['email']
    user = get_user(email)
    secret = user[3]
    totp_uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="FlaskMFA")

    if not os.path.exists("static"):
        os.makedirs("static")
    qr_path = f"static/{email}.png"
    img = qrcode.make(totp_uri)
    img.save(qr_path)

    return render_template('setup_otp.html', secret=secret, qr_path=qr_path)

# ---------------- VERIFY OTP LOGIN -----------------------------
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if 'email' not in session:
        return redirect('/')

    email = session['email']
    device_id = get_device_id()
    ip = request.remote_addr
    agent = request.headers.get('User-Agent', '')

    user = get_user(email)
    secret = user[3]
    otp_input = request.form['otp']
    totp = pyotp.TOTP(secret)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Check if device exists
    c.execute("SELECT * FROM trusted_devices WHERE email=? AND device_id=?", (email, device_id))
    device = c.fetchone()
    now = datetime.now()

    # Check device lock
    if device and device[6]:  # lock_until column index
        lock_until = device[6]
        if lock_until:
            lock_until_time = datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S.%f")
            if now < lock_until_time:
                conn.close()
                return f"Device temporarily locked until {lock_until_time}. Try later."

    if totp.verify(otp_input):
        # Successful OTP → reset failed attempts & save device if new
        if device:
            c.execute("UPDATE trusted_devices SET failed_otp_attempts=0, last_login=CURRENT_TIMESTAMP WHERE id=?", (device[0],))
        else:
            device_name = agent[:30]
            c.execute(
                "INSERT INTO trusted_devices(email, device_id, device_name, last_login, failed_otp_attempts) VALUES (?,?,?,?,0)",
                (email, device_id, device_name, now)
            )
        conn.commit()
        conn.close()
        log_action(email, f"Login Success After OTP from device {device_id} (IP: {ip})")
        return redirect('/dashboard')
    else:
        # Failed OTP → increment counter & lock if >=3
        if device:
            failed_attempts = device[5] + 1  # failed_otp_attempts column
            lock_until_time = None
            if failed_attempts >= 3:
                lock_until_time = now + timedelta(minutes=10)
            c.execute("UPDATE trusted_devices SET failed_otp_attempts=?, lock_until=? WHERE id=?",
                      (failed_attempts, lock_until_time, device[0]))
        else:
            device_name = agent[:30]
            c.execute(
                "INSERT INTO trusted_devices(email, device_id, device_name, last_login, failed_otp_attempts, lock_until) VALUES (?,?,?,?,?,?)",
                (email, device_id, device_name, now, 1, None)
            )
        conn.commit()
        conn.close()
        log_action(email, f"Failed OTP attempt from device {device_id} (IP: {ip})")
        return "Invalid OTP. Device may be locked after 3 failed attempts."

# ---------------- DASHBOARD -----------------------------
@app.route('/dashboard')
def dashboard():
    email = session.get('email')
    if not email:
        return redirect('/login')
    return render_template('dashboard.html', email=email)

# ---------------- LOGOUT -------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ---------------- AUDIT LOG ----------------------------
@app.route('/audit')
def audit():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM audit_log ORDER BY time DESC")
    logs = c.fetchall()
    conn.close()
    return render_template('audit.html', logs=logs)

# ========================================================
if __name__ == '__main__':
    if not os.path.exists("static"):
        os.makedirs("static")
    app.run(debug=True)
