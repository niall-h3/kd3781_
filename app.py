import os
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timezone
from functools import wraps
import json
import csv

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_from_directory, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_CSV_EXTENSIONS = {"csv"}
MAX_CONTENT_LENGTH = 30 * 1024 * 1024  # 30 MB

# Email (Gmail SMTP) – fill via Replit Secrets
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# ------------- Utility ------------- #
def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Ensure upload directory exists
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT NOT NULL CHECK(role IN ('admin','council')),
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_name TEXT NOT NULL,
            reporter_game_id TEXT,
            reasons TEXT NOT NULL,
            other_reason TEXT,
            evidence_type TEXT NOT NULL,
            evidence_path TEXT,
            evidence_name TEXT,
            evidence_game_id TEXT,
            coords TEXT,
            extra_info TEXT,
            submitted_at TEXT NOT NULL,
            dealt_with INTEGER DEFAULT 0,
            dealt_with_at TEXT,
            dealt_with_by INTEGER,
            FOREIGN KEY(dealt_with_by) REFERENCES users(id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mge_settings (
            id INTEGER PRIMARY KEY,
            is_open INTEGER DEFAULT 1
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mge_commanders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mge_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rok_name TEXT NOT NULL,
            profile_screenshot TEXT NOT NULL,
            power TEXT NOT NULL,
            kp TEXT NOT NULL,
            vip TEXT NOT NULL,
            unit_specialty TEXT NOT NULL,
            combat_specialty TEXT NOT NULL,
            desired_commander TEXT NOT NULL,
            has_commander TEXT NOT NULL,
            commander_photo TEXT,
            pair_commander TEXT NOT NULL,
            pair_skill_level TEXT NOT NULL,
            equipment_photo TEXT NOT NULL,
            healing_speedups TEXT NOT NULL,
            training_speedups TEXT NOT NULL,
            research_speedups TEXT NOT NULL,
            universal_speedups TEXT NOT NULL,
            building_speedups TEXT NOT NULL,
            food_resources TEXT NOT NULL,
            wood_resources TEXT NOT NULL,
            stone_resources TEXT NOT NULL,
            gold_resources TEXT NOT NULL,
            resources_photo TEXT NOT NULL,
            speedups_photo TEXT NOT NULL,
            just_unlock TEXT NOT NULL,
            gold_heads TEXT NOT NULL,
            other_info TEXT,
            submitted_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dkp_settings (
            id INTEGER PRIMARY KEY,
            is_open INTEGER DEFAULT 1,
            csv_file TEXT
        )
    """)
    conn.commit()
    conn.close()

    # Seed admin
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", ('twzytidal',))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (username,password_hash,email,role,created_at) VALUES (?,?,?,?,?)",
                (
                    'twzytidal',
                    generate_password_hash('Niall2008!'),
                    'niallhennessy08@gmail.com',
                    'admin',
                    datetime.now(timezone.utc).isoformat()
                )
            )
            conn.commit()
        
        # Initialize MGE settings
        cur.execute("SELECT id FROM mge_settings WHERE id = 1")
        if not cur.fetchone():
            cur.execute("INSERT INTO mge_settings (id, is_open) VALUES (1, 1)")
            conn.commit()
        
        # Initialize DKP settings
        cur.execute("SELECT id FROM dkp_settings WHERE id = 1")
        if not cur.fetchone():
            cur.execute("INSERT INTO dkp_settings (id, is_open, csv_file) VALUES (1, 0, NULL)")
            conn.commit()
        
        # Initialize default commanders
        default_commanders = ["Ragnar Lodbrok", "Charles Martel", "Julius Caesar"]
        for commander in default_commanders:
            cur.execute("SELECT id FROM mge_commanders WHERE name = ?", (commander,))
            if not cur.fetchone():
                cur.execute("INSERT INTO mge_commanders (name) VALUES (?)", (commander,))
        conn.commit()

def send_email(subject, body):
    if not (SMTP_USER and SMTP_PASS):
        app.logger.warning("SMTP credentials not set; email skipped.")
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    # Gather recipient emails
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT email FROM users WHERE email IS NOT NULL")
        recipients = [row['email'] for row in cur.fetchall()]
    if not recipients:
        return
    msg['To'] = ", ".join(recipients)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, recipients, msg.as_string())
    except Exception as e:
        app.logger.error(f"Email send failed: {e}")



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_csv_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_CSV_EXTENSIONS

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return redirect(url_for('login', next=request.path))
            if role:
                with connect_db() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
                    row = cur.fetchone()
                    if row and row['role'] != role and row['role'] != 'admin':
                        flash("Unauthorized.", "danger")
                        return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ------------- Routes ------------- #
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/mge", methods=['GET', 'POST'])
def mge_application():
    # Check if MGE is open
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT is_open FROM mge_settings WHERE id = 1")
        is_open = cur.fetchone()['is_open']
        if not is_open:
            flash("MGE applications are currently closed.", "warning")
            return redirect(url_for('home'))
        
        # Get available commanders
        cur.execute("SELECT name FROM mge_commanders ORDER BY name")
        commanders = [row['name'] for row in cur.fetchall()]
    
    if request.method == 'POST':
        # Handle file uploads
        profile_screenshot = request.files.get('profile_screenshot')
        if not (profile_screenshot and profile_screenshot.filename and allowed_file(profile_screenshot.filename)):
            flash("Invalid or missing profile screenshot.", "danger")
            return redirect(request.url)
        
        profile_filename = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + secure_filename(profile_screenshot.filename)
        profile_screenshot.save(os.path.join(UPLOAD_DIR, profile_filename))
        
        equipment_photo = request.files.get('equipment_photo')
        if not (equipment_photo and equipment_photo.filename and allowed_file(equipment_photo.filename)):
            flash("Invalid or missing equipment photo.", "danger")
            return redirect(request.url)
        
        equipment_filename = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + secure_filename(equipment_photo.filename)
        equipment_photo.save(os.path.join(UPLOAD_DIR, equipment_filename))
        
        resources_photo = request.files.get('resources_photo')
        if not (resources_photo and resources_photo.filename and allowed_file(resources_photo.filename)):
            flash("Invalid or missing resources photo.", "danger")
            return redirect(request.url)
        
        resources_filename = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + secure_filename(resources_photo.filename)
        resources_photo.save(os.path.join(UPLOAD_DIR, resources_filename))
        
        speedups_photo = request.files.get('speedups_photo')
        if not (speedups_photo and speedups_photo.filename and allowed_file(speedups_photo.filename)):
            flash("Invalid or missing speedups photo.", "danger")
            return redirect(request.url)
        
        speedups_filename = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + secure_filename(speedups_photo.filename)
        speedups_photo.save(os.path.join(UPLOAD_DIR, speedups_filename))
        
        # Handle optional commander photo
        commander_photo_filename = None
        has_commander = request.form['has_commander']
        if has_commander == 'Yes':
            commander_photo = request.files.get('commander_photo')
            if commander_photo and commander_photo.filename and allowed_file(commander_photo.filename):
                commander_photo_filename = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + secure_filename(commander_photo.filename)
                commander_photo.save(os.path.join(UPLOAD_DIR, commander_photo_filename))
        
        # Get form data
        unit_specialty = json.dumps(request.form.getlist('unit_specialty'))
        combat_specialty = json.dumps(request.form.getlist('combat_specialty'))
        
        with connect_db() as conn:
            cur = conn.cursor()
            cur.execute("""INSERT INTO mge_applications 
                (rok_name, profile_screenshot, power, kp, vip, unit_specialty, combat_specialty,
                 desired_commander, has_commander, commander_photo, pair_commander, pair_skill_level,
                 equipment_photo, healing_speedups, training_speedups, research_speedups, 
                 universal_speedups, building_speedups, food_resources, wood_resources, 
                 stone_resources, gold_resources, resources_photo, speedups_photo, 
                 just_unlock, gold_heads, other_info, submitted_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    request.form['rok_name'],
                    profile_filename,
                    request.form['power'],
                    request.form['kp'],
                    request.form['vip'],
                    unit_specialty,
                    combat_specialty,
                    request.form['desired_commander'],
                    has_commander,
                    commander_photo_filename,
                    request.form['pair_commander'],
                    request.form['pair_skill_level'],
                    equipment_filename,
                    request.form['healing_speedups'],
                    request.form['training_speedups'],
                    request.form['research_speedups'],
                    request.form['universal_speedups'],
                    request.form['building_speedups'],
                    request.form['food_resources'],
                    request.form['wood_resources'],
                    request.form['stone_resources'],
                    request.form['gold_resources'],
                    resources_filename,
                    speedups_filename,
                    request.form['just_unlock'],
                    request.form['gold_heads'],
                    request.form.get('other_info'),
                    datetime.now(timezone.utc).isoformat()
                ))
            application_id = cur.lastrowid
            conn.commit()
        
        return render_template("mge_submitted.html", application_id=application_id)
    
    return render_template("mge_form.html", commanders=commanders)

@app.route("/report", methods=['GET', 'POST'])
def report():
    if request.method == 'POST':
        name = request.form['reporter_name']
        game_id = request.form.get('reporter_game_id') or None
        reasons = request.form.getlist('reason')
        if 'Other' in reasons:
            other_reason = request.form.get('other_reason')
        else:
            other_reason = None
        evidence_choice = request.form['evidence_choice']
        evidence_type = 'photo' if evidence_choice == 'photo' else 'text'
        evidence_path = None
        evidence_name = None
        evidence_game_id = None

        if evidence_type == 'photo':
            file = request.files.get('evidence_photo')
            if not (file and file.filename and allowed_file(file.filename)):
                flash("Invalid or missing photo.", "danger")
                return redirect(request.url)
            filename = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_DIR, filename))
            evidence_path = filename
        else:
            evidence_name = request.form.get('evidence_name')
            evidence_game_id = request.form.get('evidence_id')
            if not evidence_name or not evidence_game_id:
                flash("Please provide both name and ID when selecting 'Name and ID' option.", "danger")
                return redirect(request.url)

        coords = request.form.get('coords') or None
        extra_info = request.form.get('extra_info') or None

        with connect_db() as conn:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO reports
                (reporter_name, reporter_game_id, reasons, other_reason,
                 evidence_type, evidence_path, evidence_name, evidence_game_id,
                 coords, extra_info, submitted_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (
                    name, game_id, json.dumps(reasons), other_reason,
                    evidence_type, evidence_path, evidence_name, evidence_game_id,
                    coords, extra_info, datetime.now(timezone.utc).isoformat()
                )
            )
            report_id = cur.lastrowid
            conn.commit()

        # Email notification
        send_email(
            subject=f"New Report #{report_id}",
            body=f"Report #{report_id} submitted by {name} at {datetime.utcnow().isoformat()} UTC."
        )

        return render_template("report_submitted.html", report_id=report_id)

    return render_template("report_form.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with connect_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row and check_password_hash(row['password_hash'], password):
                session['user_id'] = row['id']
                flash("Logged in.", "success")
                return redirect(request.args.get('next') or url_for('dashboard'))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash("Logged out.", "info")
    return redirect(url_for('home'))

@app.route("/dashboard")
@login_required()
def dashboard():
    user_id = session['user_id']
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        role = cur.fetchone()['role']
    return render_template("dashboard.html", role=role)

@app.route("/reports")
@login_required()
def reports():
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, submitted_at FROM reports WHERE dealt_with = 0 ORDER BY submitted_at DESC")
        reports = cur.fetchall()
    return render_template("reports.html", reports=reports)

@app.route("/reports/dealt")
@login_required()
def dealt_reports():
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("""SELECT r.id, r.submitted_at, r.dealt_with_at, u.username AS dealt_by
                       FROM reports r LEFT JOIN users u ON u.id = r.dealt_with_by
                       WHERE r.dealt_with = 1 ORDER BY r.dealt_with_at DESC""")
        reports = cur.fetchall()
    return render_template("dealt_with.html", reports=reports)

def get_report_or_404(report_id):
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        report = cur.fetchone()
    if not report:
        return None
    return report

@app.route("/report/<int:report_id>", methods=['GET', 'POST'])
@login_required()
def view_report(report_id):
    report = get_report_or_404(report_id)
    if report is None:
        flash("Report not found.", "warning")
        return redirect(url_for('reports'))
    # Actions
    if request.method == 'POST':
        action = request.form['action']
        user_id = session['user_id']
        with connect_db() as conn:
            cur = conn.cursor()
            if action == 'deal':
                cur.execute("""UPDATE reports SET dealt_with = 1,
                            dealt_with_at = ?, dealt_with_by = ?
                            WHERE id = ?""", (
                                datetime.now(timezone.utc).isoformat(),
                                user_id,
                                report_id
                            ))
                conn.commit()
                flash("Marked as dealt with.", "success")
                return redirect(url_for('reports'))
            elif action == 'undeal':
                cur.execute("""UPDATE reports SET dealt_with = 0,
                                dealt_with_at = NULL, dealt_with_by = NULL
                                WHERE id = ?""", (report_id,))
                conn.commit()
                flash("Marked as not dealt with.", "info")
                return redirect(url_for('dealt_reports'))
            elif action == 'delete':
                # Verify admin
                cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
                role = cur.fetchone()['role']
                if role != 'admin':
                    flash("Admins only.", "danger")
                else:
                    cur.execute("DELETE FROM reports WHERE id = ?", (report_id,))
                    conn.commit()
                    flash("Report deleted.", "info")
                return redirect(url_for('reports'))

    return render_template("view_report.html", report=report, json=json, datetime=datetime, timezone=timezone)

@app.route("/add_user", methods=['GET', 'POST'])
@login_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        email = request.form.get('email') or None
        with connect_db() as conn:
            cur = conn.cursor()
            try:
                cur.execute("""INSERT INTO users
                            (username,password_hash,email,role,created_at)
                            VALUES (?,?,?,?,?)""", (
                                username,
                                generate_password_hash(password),
                                email,
                                role,
                                datetime.now(timezone.utc).isoformat()
                            ))
                conn.commit()
                flash("User added.", "success")
            except sqlite3.IntegrityError:
                flash("Username already exists.", "danger")
    return render_template("add_user.html")

# MGE Management Routes
@app.route("/mge_management")
@login_required()
def mge_management():
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT is_open FROM mge_settings WHERE id = 1")
        is_open = cur.fetchone()['is_open']
    return render_template("mge_management.html", is_open=is_open)

@app.route("/mge_toggle", methods=['POST'])
@login_required()
def mge_toggle():
    action = request.form['action']
    new_status = 1 if action == 'open' else 0
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE mge_settings SET is_open = ? WHERE id = 1", (new_status,))
        conn.commit()
    flash(f"MGE {'opened' if new_status else 'closed'}.", "success")
    return redirect(url_for('mge_management'))

@app.route("/add_commander", methods=['GET', 'POST'])
@login_required()
def add_commander():
    if request.method == 'POST':
        commander_name = request.form['commander_name']
        with connect_db() as conn:
            cur = conn.cursor()
            try:
                cur.execute("INSERT INTO mge_commanders (name) VALUES (?)", (commander_name,))
                conn.commit()
                flash("Commander added.", "success")
            except sqlite3.IntegrityError:
                flash("Commander already exists.", "danger")
        return redirect(url_for('mge_management'))
    return render_template("add_commander.html")

@app.route("/mge_applications")
@login_required()
def mge_applications():
    user_id = session['user_id']
    sort_by = request.args.get('sort', 'submitted_at')
    sort_order = request.args.get('order', 'desc')
    
    # Valid sort options
    valid_sorts = {
        'name': 'rok_name',
        'power': 'CAST(power AS INTEGER)',
        'kp': 'CAST(kp AS INTEGER)', 
        'total_resources': '(CAST(food_resources AS INTEGER) + CAST(wood_resources AS INTEGER) + CAST(stone_resources AS INTEGER) + CAST(gold_resources AS INTEGER))',
        'total_speedups': '(CAST(healing_speedups AS INTEGER) + CAST(training_speedups AS INTEGER) + CAST(research_speedups AS INTEGER) + CAST(universal_speedups AS INTEGER) + CAST(building_speedups AS INTEGER))',
        'submitted_at': 'submitted_at'
    }
    
    order_clause = valid_sorts.get(sort_by, 'submitted_at')
    if sort_order == 'desc':
        order_clause += ' DESC'
    else:
        order_clause += ' ASC'
    
    with connect_db() as conn:
        cur = conn.cursor()
        query = f"""SELECT id, rok_name, power, kp, submitted_at,
                    food_resources, wood_resources, stone_resources, gold_resources,
                    healing_speedups, training_speedups, research_speedups, universal_speedups, building_speedups,
                    (CAST(food_resources AS INTEGER) + CAST(wood_resources AS INTEGER) + CAST(stone_resources AS INTEGER) + CAST(gold_resources AS INTEGER)) as total_resources,
                    (CAST(healing_speedups AS INTEGER) + CAST(training_speedups AS INTEGER) + CAST(research_speedups AS INTEGER) + CAST(universal_speedups AS INTEGER) + CAST(building_speedups AS INTEGER)) as total_speedups
                    FROM mge_applications ORDER BY {order_clause}"""
        cur.execute(query)
        applications = cur.fetchall()
        cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        role = cur.fetchone()['role']
    return render_template("mge_applications.html", applications=applications, role=role, current_sort=sort_by, current_order=sort_order)

@app.route("/mge_application/<int:application_id>", methods=['GET', 'POST'])
@login_required()
def view_mge_application(application_id):
    user_id = session['user_id']
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM mge_applications WHERE id = ?", (application_id,))
        application = cur.fetchone()
        
        if not application:
            flash("Application not found.", "warning")
            return redirect(url_for('mge_applications'))
        
        cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        role = cur.fetchone()['role']
        
        if request.method == 'POST':
            action = request.form['action']
            
            if action == 'delete':
                # Verify admin
                if role != 'admin':
                    flash("Admins only.", "danger")
                else:
                    cur.execute("DELETE FROM mge_applications WHERE id = ?", (application_id,))
                    conn.commit()
                    flash("Application deleted.", "info")
                return redirect(url_for('mge_applications'))
    
    return render_template("view_mge_application.html", application=application, role=role, json=json)

@app.route("/delete_all_mge", methods=['POST'])
@login_required('admin')
def delete_all_mge():
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM mge_applications")
        conn.commit()
    flash("All MGE applications deleted.", "info")
    return redirect(url_for('mge_applications'))

# DKP Management Routes
@app.route("/dkp_management")
@login_required('admin')
def dkp_management():
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT is_open, csv_file FROM dkp_settings WHERE id = 1")
        settings = cur.fetchone()
        is_open = settings['is_open']
        csv_file = settings['csv_file']
    return render_template("dkp_management.html", is_open=is_open, csv_file=csv_file)

@app.route("/dkp_toggle", methods=['POST'])
@login_required('admin')
def dkp_toggle():
    action = request.form['action']
    new_status = 1 if action == 'open' else 0
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE dkp_settings SET is_open = ? WHERE id = 1", (new_status,))
        conn.commit()
    flash(f"DKP {'opened' if new_status else 'closed'}.", "success")
    return redirect(url_for('dkp_management'))

@app.route("/upload_dkp", methods=['POST'])
@login_required('admin')
def upload_dkp():
    file = request.files.get('dkp_file')
    if not (file and file.filename and allowed_csv_file(file.filename)):
        flash("Invalid or missing CSV file.", "danger")
        return redirect(url_for('dkp_management'))
    
    filename = "dkp_data.csv"
    file_path = os.path.join(UPLOAD_DIR, filename)
    file.save(file_path)
    
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE dkp_settings SET csv_file = ? WHERE id = 1", (filename,))
        conn.commit()
    
    flash("DKP file uploaded successfully.", "success")
    return redirect(url_for('dkp_management'))

@app.route("/delete_dkp", methods=['POST'])
@login_required('admin')
def delete_dkp():
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT csv_file FROM dkp_settings WHERE id = 1")
        csv_file = cur.fetchone()['csv_file']
        
        if csv_file:
            file_path = os.path.join(UPLOAD_DIR, csv_file)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        cur.execute("UPDATE dkp_settings SET csv_file = NULL WHERE id = 1", )
        conn.commit()
    
    flash("DKP file deleted.", "info")
    return redirect(url_for('dkp_management'))

@app.route("/view_dkp")
def view_dkp():
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT is_open, csv_file FROM dkp_settings WHERE id = 1")
        settings = cur.fetchone()
        
        if not settings['is_open']:
            flash("DKP viewing is currently closed.", "warning")
            return redirect(url_for('home'))
        
        if not settings['csv_file']:
            flash("No DKP data available.", "warning")
            return redirect(url_for('home'))
        
        # Read CSV data
        csv_path = os.path.join(UPLOAD_DIR, settings['csv_file'])
        all_rows = []
        headers = []
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                all_rows = list(reader)
                if all_rows:
                    headers = all_rows[0]  # First row is headers
                    data_rows = all_rows[1:]  # Rest are data
                else:
                    data_rows = []
        except Exception as e:
            flash("Error reading DKP data.", "danger")
            return redirect(url_for('home'))
    
    # Handle search and sorting
    search_name = request.args.get('search_name', '').strip()
    search_id = request.args.get('search_id', '').strip()
    sort_by = request.args.get('sort', '')
    
    filtered_data = data_rows
    
    # Apply search filters (only on data rows, not headers)
    if search_name:
        filtered_data = [row for row in filtered_data if len(row) > 0 and search_name.lower() in row[0].lower()]
    
    if search_id:
        filtered_data = [row for row in filtered_data if len(row) > 1 and search_id in row[1]]
    
    # Apply sorting (only on data rows, not headers)
    if sort_by == 'last' and headers and len(headers) > 0:
        try:
            filtered_data.sort(key=lambda x: float(x[-1]) if len(x) > 0 and x[-1].replace('.', '').replace('-', '').isdigit() else 0, reverse=True)
        except:
            pass
    elif sort_by == 'second_last' and headers and len(headers) > 1:
        try:
            filtered_data.sort(key=lambda x: float(x[-2]) if len(x) > 1 and x[-2].replace('.', '').replace('-', '').isdigit() else 0, reverse=True)
        except:
            pass
    
    return render_template("view_dkp.html", headers=headers, data=filtered_data, 
                         search_name=search_name, search_id=search_id, sort_by=sort_by)

# Static uploads serve (simple)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
