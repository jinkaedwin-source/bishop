import csv
import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "mp3",
    "mp4",
    "mov",
    "m4a",
    "wav",
    "pdf",
    "doc",
    "docx",
    "txt",
    "rtf",
}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key-before-production")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024
MAX_FAILED_LOGINS = 5
LOCKOUT_WINDOW_MINUTES = 15


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file, folder):
    if not file or not file.filename:
        return None
    if not allowed_file(file.filename):
        flash("Unsupported file type.", "error")
        return None
    target_folder = os.path.join(app.config["UPLOAD_FOLDER"], folder)
    os.makedirs(target_folder, exist_ok=True)
    filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secure_filename(file.filename)}"
    file.save(os.path.join(target_folder, filename))
    return f"uploads/{folder}/{filename}"


def client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def log_security_event(event_type, message, email="", severity="info"):
    db = get_db()
    db.execute(
        """INSERT INTO security_events (event_type, email, ip_address, message, severity)
           VALUES (?, ?, ?, ?, ?)""",
        (event_type, email, client_ip(), message, severity),
    )
    db.commit()


def recent_failed_login_count(email):
    return get_db().execute(
        """SELECT COUNT(*) FROM security_events
           WHERE event_type = 'failed_login'
           AND email = ?
           AND created_at >= datetime('now', ?)""",
        (email, f"-{LOCKOUT_WINDOW_MINUTES} minutes"),
    ).fetchone()[0]


def account_temporarily_locked(email):
    return recent_failed_login_count(email) >= MAX_FAILED_LOGINS


def bishop_chat_reply(message):
    text = message.lower()
    blocked_terms = [
        "admin password",
        "admin login",
        "database",
        "secret key",
        "credentials",
        "confidential",
        "hack",
        "sql",
        "private data",
        "prayer requests list",
    ]
    if any(term in text for term in blocked_terms):
        return (
            "I am BISHOP, the ministry assistant. I cannot provide admin login details, "
            "credentials, private records, database information, or confidential site information. "
            "For official help, please contact the ministry office through the Contact page."
        )

    if any(word in text for word in ["pray", "prayer", "anxious", "sick", "help me", "family"]):
        return (
            "Short prayer: Father, in the name of Jesus Christ, strengthen this visitor with peace, "
            "wisdom, healing, and faith. Let Your light guide their steps today. Amen. "
            "You may also submit a private request on the Prayer page: /prayer"
        )

    if any(word in text for word in ["sermon", "preaching", "message", "video", "audio"]):
        return "You can watch or listen to ministry messages on the Sermons page: /sermons"

    if any(word in text for word in ["devotional", "daily", "verse", "bible verse"]):
        return "For daily encouragement and Scripture reflection, visit the Devotionals page: /devotionals"

    if any(word in text for word in ["event", "conference", "crusade", "program", "service"]):
        return "You can see services, programs, conferences, and crusades on the Events page: /events"

    if any(word in text for word in ["partner", "support", "give", "donate", "offering", "tithe"]):
        return "To support or partner with LIGHT INTERNATIONAL MINISTRY, visit /partner or the Donation page: /donate"

    if any(word in text for word in ["about", "ministry", "church", "vision", "mission"]):
        return (
            "LIGHT INTERNATIONAL MINISTRY is a Christian church and ministry focused on worship, "
            "discipleship, prayer, evangelism, and compassionate service. Learn more here: /about"
        )

    if any(word in text for word in ["pastor", "leader", "leaders"]):
        return "You can learn about the pastor and ministry leaders on /pastor and /leaders"

    if any(word in text for word in ["contact", "address", "email", "visit"]):
        return "For ministry contact, service times, and visit information, please use the Contact page: /contact"

    return (
        "I am BISHOP, your ministry assistant. I can help with short prayers, sermons, devotionals, "
        "events, partnership, giving, prayer requests, and information about LIGHT INTERNATIONAL MINISTRY. "
        "How may I guide you today?"
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access is required.", "error")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def init_db(seed=True):
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS sermons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            preacher TEXT NOT NULL,
            scripture TEXT,
            summary TEXT,
            content TEXT,
            category_id INTEGER,
            thumbnail TEXT,
            audio_url TEXT,
            video_url TEXT,
            featured INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(category_id) REFERENCES categories(id)
        );

        CREATE TABLE IF NOT EXISTS devotionals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            scripture TEXT,
            content TEXT NOT NULL,
            category_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(category_id) REFERENCES categories(id)
        );

        CREATE TABLE IF NOT EXISTS bible_studies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            teacher TEXT,
            scripture TEXT,
            description TEXT,
            meeting_time TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            event_date TEXT NOT NULL,
            location TEXT,
            description TEXT,
            event_type TEXT DEFAULT 'Program'
        );

        CREATE TABLE IF NOT EXISTS prayer_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            message TEXT NOT NULL,
            attachment TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS partners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            country TEXT NOT NULL,
            city TEXT,
            partnership_type TEXT,
            message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT NOT NULL,
            body TEXT NOT NULL,
            content_type TEXT NOT NULL,
            content_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS newsletters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS testimonies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            testimony TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS gallery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            image_path TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            email TEXT,
            ip_address TEXT,
            message TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    columns = [row["name"] for row in db.execute("PRAGMA table_info(prayer_requests)").fetchall()]
    if "attachment" not in columns:
        db.execute("ALTER TABLE prayer_requests ADD COLUMN attachment TEXT")

    if not seed:
        db.commit()
        db.close()
        return

    existing = db.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
    if existing == 0:
        categories = [
            ("Faith", "Trusting God in every season."),
            ("Prayer", "Teaching and encouragement for a deeper prayer life."),
            ("Salvation", "The gospel of Jesus Christ and new life in Him."),
            ("Worship", "Living a life that honors God."),
            ("Youth", "Discipleship and leadership for young believers."),
            ("Marriage", "Christ-centered family and covenant teaching."),
            ("Deliverance", "Freedom, healing, and victory in Christ."),
        ]
        db.executemany("INSERT INTO categories (name, description) VALUES (?, ?)", categories)

    cat_ids = {row["name"]: row["id"] for row in db.execute("SELECT id, name FROM categories")}

    if db.execute("SELECT COUNT(*) FROM sermons").fetchone()[0] == 0:
        sermons = [
            ("Walking in the Light", "Pastor Daniel Mensah", "John 8:12", "Jesus is the light that guides every believer.", "A message on following Christ with courage, purity, and daily obedience.", cat_ids["Faith"], "", "", "https://www.youtube.com/embed/dQw4w9WgXcQ", 1),
            ("The Power of Midnight Prayer", "Pastor Daniel Mensah", "Acts 16:25-26", "Prayer opens prison doors and renews faith.", "This sermon teaches persistence, worship, and spiritual authority in prayer.", cat_ids["Prayer"], "", "", "", 1),
            ("Grace That Saves", "Minister Abigail Stone", "Ephesians 2:8-9", "Salvation is God's gift through Jesus Christ.", "A clear gospel message for seekers, new believers, and growing disciples.", cat_ids["Salvation"], "", "", "", 0),
        ]
        db.executemany(
            """INSERT INTO sermons
            (title, preacher, scripture, summary, content, category_id, thumbnail, audio_url, video_url, featured)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            sermons,
        )

    if db.execute("SELECT COUNT(*) FROM devotionals").fetchone()[0] == 0:
        devotionals = [
            ("Strength for Today", "Isaiah 40:31", "Wait on the Lord today. His strength is not fragile, and His timing is full of wisdom.", cat_ids["Faith"]),
            ("A Heart Ready to Pray", "1 Thessalonians 5:17", "Prayer keeps the heart awake to God's voice in ordinary moments.", cat_ids["Prayer"]),
            ("Worship in Spirit and Truth", "John 4:24", "True worship begins with surrender and becomes visible through obedience.", cat_ids["Worship"]),
        ]
        db.executemany(
            "INSERT INTO devotionals (title, scripture, content, category_id) VALUES (?, ?, ?, ?)",
            devotionals,
        )

    if db.execute("SELECT COUNT(*) FROM bible_studies").fetchone()[0] == 0:
        studies = [
            ("Foundations of Faith", "Elder Miriam Cole", "Hebrews 11", "A weekly study on faith, obedience, and spiritual maturity.", "Wednesdays, 6:30 PM"),
            ("The Life of Christ", "Pastor Daniel Mensah", "Luke 1-24", "A chapter-by-chapter journey through the ministry of Jesus.", "Saturdays, 10:00 AM"),
        ]
        db.executemany(
            "INSERT INTO bible_studies (title, teacher, scripture, description, meeting_time) VALUES (?, ?, ?, ?, ?)",
            studies,
        )

    if db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0:
        events = [
            ("Sunday Celebration Service", "2026-06-07", "Main Sanctuary", "Worship, teaching, prayer, and fellowship for all families.", "Service"),
            ("Youth Ablaze Night", "2026-06-12", "Youth Hall", "A night of worship, discipleship, and purpose for young believers.", "Program"),
            ("Kingdom Light Conference", "2026-07-18", "LIGHT International Ministry Campus", "Three days of word, worship, prayer, healing, and mission training.", "Conference"),
            ("Citywide Gospel Crusade", "2026-08-22", "Central Community Field", "An open-air evangelistic crusade centered on Christ and salvation.", "Crusade"),
        ]
        db.executemany(
            "INSERT INTO events (title, event_date, location, description, event_type) VALUES (?, ?, ?, ?, ?)",
            events,
        )

    if db.execute("SELECT COUNT(*) FROM testimonies").fetchone()[0] == 0:
        testimonies = [
            ("Sister Grace", "God restored peace in my family through prayer and biblical counsel."),
            ("Brother Michael", "After months of discouragement, the Lord renewed my faith and opened a new door."),
        ]
        db.executemany("INSERT INTO testimonies (name, testimony) VALUES (?, ?)", testimonies)

    if db.execute("SELECT COUNT(*) FROM gallery").fetchone()[0] == 0:
        galleries = [
            ("Worship Service", "https://images.unsplash.com/photo-1438032005730-c779502df39b?auto=format&fit=crop&w=900&q=80"),
            ("Community Prayer", "https://images.unsplash.com/photo-1490730141103-6cac27aaab94?auto=format&fit=crop&w=900&q=80"),
            ("Bible Study Fellowship", "https://images.unsplash.com/photo-1504052434569-70ad5836ab65?auto=format&fit=crop&w=900&q=80"),
        ]
        db.executemany("INSERT INTO gallery (title, image_path) VALUES (?, ?)", galleries)

    admin_exists = db.execute(
        "SELECT COUNT(*) FROM users WHERE email = ?",
        ("admin@lightministry.local",),
    ).fetchone()[0]
    if admin_exists == 0:
        db.execute(
            "INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
            ("Admin", "admin@lightministry.local", generate_password_hash("Admin123!"), 1),
        )

    db.commit()
    db.close()


def fetch_home_data():
    db = get_db()
    return {
        "featured_sermons": db.execute(
            """SELECT sermons.*, categories.name AS category FROM sermons
               LEFT JOIN categories ON sermons.category_id = categories.id
               WHERE featured = 1 ORDER BY sermons.created_at DESC LIMIT 3"""
        ).fetchall(),
        "latest_sermons": db.execute(
            """SELECT sermons.*, categories.name AS category FROM sermons
               LEFT JOIN categories ON sermons.category_id = categories.id
               ORDER BY sermons.created_at DESC LIMIT 6"""
        ).fetchall(),
        "devotionals": db.execute(
            """SELECT devotionals.*, categories.name AS category FROM devotionals
               LEFT JOIN categories ON devotionals.category_id = categories.id
               ORDER BY devotionals.created_at DESC LIMIT 3"""
        ).fetchall(),
        "studies": db.execute("SELECT * FROM bible_studies LIMIT 3").fetchall(),
        "events": db.execute("SELECT * FROM events ORDER BY event_date ASC LIMIT 4").fetchall(),
        "testimonies": db.execute("SELECT * FROM testimonies ORDER BY created_at DESC LIMIT 3").fetchall(),
        "gallery": db.execute("SELECT * FROM gallery ORDER BY created_at DESC LIMIT 6").fetchall(),
    }


@app.route("/")
def home():
    return render_template("home.html", **fetch_home_data())


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/pastor")
def pastor():
    return render_template("pastor.html")


@app.route("/leaders")
def leaders():
    return render_template("leaders.html")


@app.route("/sermons")
def sermons():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    db = get_db()
    params = []
    sql = """SELECT sermons.*, categories.name AS category FROM sermons
             LEFT JOIN categories ON sermons.category_id = categories.id WHERE 1=1"""
    if q:
        sql += " AND (sermons.title LIKE ? OR sermons.summary LIKE ? OR sermons.content LIKE ? OR sermons.scripture LIKE ?)"
        params.extend([f"%{q}%"] * 4)
    if category:
        sql += " AND categories.name = ?"
        params.append(category)
    sql += " ORDER BY sermons.created_at DESC"
    rows = db.execute(sql, params).fetchall()
    categories = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    return render_template("sermons.html", sermons=rows, categories=categories, q=q, selected_category=category)


@app.route("/sermon/<int:sermon_id>", methods=["GET", "POST"])
def sermon_detail(sermon_id):
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        body = request.form.get("body", "").strip()
        if name and body:
            db.execute(
                "INSERT INTO comments (user_name, body, content_type, content_id) VALUES (?, ?, 'sermon', ?)",
                (name, body, sermon_id),
            )
            db.commit()
            flash("Comment added.", "success")
        return redirect(url_for("sermon_detail", sermon_id=sermon_id))

    sermon = db.execute(
        """SELECT sermons.*, categories.name AS category FROM sermons
           LEFT JOIN categories ON sermons.category_id = categories.id WHERE sermons.id = ?""",
        (sermon_id,),
    ).fetchone()
    if sermon is None:
        return render_template("404.html"), 404
    comments = db.execute(
        "SELECT * FROM comments WHERE content_type = 'sermon' AND content_id = ? ORDER BY created_at DESC",
        (sermon_id,),
    ).fetchall()
    return render_template("sermon_detail.html", sermon=sermon, comments=comments)


@app.route("/devotionals", methods=["GET", "POST"])
def devotionals():
    db = get_db()
    q = request.args.get("q", "").strip()
    params = []
    sql = """SELECT devotionals.*, categories.name AS category FROM devotionals
             LEFT JOIN categories ON devotionals.category_id = categories.id WHERE 1=1"""
    if q:
        sql += " AND (devotionals.title LIKE ? OR devotionals.content LIKE ? OR devotionals.scripture LIKE ?)"
        params.extend([f"%{q}%"] * 3)
    sql += " ORDER BY devotionals.created_at DESC"
    rows = db.execute(sql, params).fetchall()
    return render_template("devotionals.html", devotionals=rows, q=q)


@app.route("/devotional/<int:devotional_id>", methods=["POST"])
def devotional_comment(devotional_id):
    db = get_db()
    name = request.form.get("name", "").strip()
    body = request.form.get("body", "").strip()
    if name and body:
        db.execute(
            "INSERT INTO comments (user_name, body, content_type, content_id) VALUES (?, ?, 'devotional', ?)",
            (name, body, devotional_id),
        )
        db.commit()
        flash("Comment added.", "success")
    return redirect(url_for("devotionals"))


@app.route("/bible-studies")
def bible_studies():
    studies = get_db().execute("SELECT * FROM bible_studies").fetchall()
    return render_template("bible_studies.html", studies=studies)


@app.route("/events")
def events():
    rows = get_db().execute("SELECT * FROM events ORDER BY event_date ASC").fetchall()
    return render_template("events.html", events=rows)


@app.route("/categories")
def categories():
    rows = get_db().execute("SELECT * FROM categories ORDER BY name").fetchall()
    return render_template("categories.html", categories=rows)


@app.route("/prayer", methods=["GET", "POST"])
def prayer():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()
        if not name or not message:
            flash("Name and prayer request are required.", "error")
        else:
            attachment = save_upload(request.files.get("attachment"), "prayers")
            db = get_db()
            db.execute(
                "INSERT INTO prayer_requests (name, email, message, attachment) VALUES (?, ?, ?, ?)",
                (name, email, message, attachment or ""),
            )
            db.commit()
            flash("Your prayer request has been received.", "success")
            return redirect(url_for("prayer"))
    return render_template("prayer.html")


@app.route("/partner", methods=["GET", "POST"])
def partner():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        country = request.form.get("country", "").strip()
        if not name or not email or not country:
            flash("Name, email, and country are required.", "error")
        else:
            db = get_db()
            db.execute(
                """INSERT INTO partners
                (name, email, phone, country, city, partnership_type, message)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    name,
                    email,
                    request.form.get("phone", "").strip(),
                    country,
                    request.form.get("city", "").strip(),
                    request.form.get("partnership_type", "").strip(),
                    request.form.get("message", "").strip(),
                ),
            )
            db.commit()
            flash("Thank you for partnering with LIGHT INTERNATIONAL MINISTRY.", "success")
            return redirect(url_for("partner"))
    return render_template("partner.html")


@app.route("/donate")
def donate():
    return render_template("donate.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        flash("Thank you for contacting LIGHT INTERNATIONAL MINISTRY.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")


@app.route("/newsletter", methods=["POST"])
def newsletter():
    email = request.form.get("email", "").strip().lower()
    if email:
        try:
            db = get_db()
            db.execute("INSERT INTO newsletters (email) VALUES (?)", (email,))
            db.commit()
            flash("You are subscribed to ministry updates.", "success")
        except sqlite3.IntegrityError:
            flash("This email is already subscribed.", "error")
    return redirect(request.referrer or url_for("home"))


@app.route("/ai-chat", methods=["POST"])
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"reply": "Please type a question or prayer request so BISHOP can help."})
    return jsonify({"reply": bishop_chat_reply(message[:700])})


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif name and email:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, generate_password_hash(password)),
                )
                db.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("An account already exists for that email.", "error")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if account_temporarily_locked(email):
            log_security_event("blocked_login", "User login blocked after repeated failed attempts.", email, "high")
            flash("Too many failed attempts. Please wait 15 minutes before trying again.", "error")
            return render_template("auth.html", mode="login")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["is_admin"] = bool(user["is_admin"])
            log_security_event("successful_login", "User login successful.", email, "info")
            flash("Welcome back.", "success")
            return redirect(url_for("home"))
        log_security_event("failed_login", "Invalid user login attempt.", email, "medium")
        flash("Invalid email or password.", "error")
    return render_template("auth.html", mode="login")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if account_temporarily_locked(email):
            log_security_event("blocked_login", "Admin login blocked after repeated failed attempts.", email, "critical")
            flash("Too many failed attempts. Please wait 15 minutes before trying again.", "error")
            return render_template("auth.html", mode="admin")
        user = get_db().execute("SELECT * FROM users WHERE email = ? AND is_admin = 1", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["is_admin"] = True
            log_security_event("successful_admin_login", "Admin login successful.", email, "info")
            return redirect(url_for("admin_dashboard"))
        log_security_event("failed_login", "Invalid admin login attempt.", email, "high")
        flash("Invalid admin credentials.", "error")
    return render_template("auth.html", mode="admin")


@app.route("/logout")
def logout():
    if session.get("user_id"):
        log_security_event("logout", "User logged out.", session.get("name", ""), "info")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    stats = {
        "sermons": db.execute("SELECT COUNT(*) FROM sermons").fetchone()[0],
        "devotionals": db.execute("SELECT COUNT(*) FROM devotionals").fetchone()[0],
        "events": db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "prayers": db.execute("SELECT COUNT(*) FROM prayer_requests").fetchone()[0],
        "security_alerts": db.execute(
            """SELECT COUNT(*) FROM security_events
               WHERE severity IN ('high', 'critical')
               AND created_at >= datetime('now', '-7 days')"""
        ).fetchone()[0],
    }
    recent_alerts = db.execute(
        "SELECT * FROM security_events ORDER BY created_at DESC LIMIT 5"
    ).fetchall()
    return render_template("admin.html", stats=stats, recent_alerts=recent_alerts)


@app.route("/admin/security")
@admin_required
def admin_security():
    db = get_db()
    events = db.execute(
        "SELECT * FROM security_events ORDER BY created_at DESC LIMIT 100"
    ).fetchall()
    failed_last_day = db.execute(
        """SELECT COUNT(*) FROM security_events
           WHERE event_type = 'failed_login'
           AND created_at >= datetime('now', '-1 day')"""
    ).fetchone()[0]
    blocked_last_day = db.execute(
        """SELECT COUNT(*) FROM security_events
           WHERE event_type = 'blocked_login'
           AND created_at >= datetime('now', '-1 day')"""
    ).fetchone()[0]
    return render_template(
        "admin_security.html",
        events=events,
        failed_last_day=failed_last_day,
        blocked_last_day=blocked_last_day,
        max_failed=MAX_FAILED_LOGINS,
        lockout_minutes=LOCKOUT_WINDOW_MINUTES,
    )


@app.route("/admin/sermons", methods=["GET", "POST"])
@admin_required
def admin_sermons():
    db = get_db()
    if request.method == "POST":
        thumbnail = save_upload(request.files.get("thumbnail"), "sermons")
        db.execute(
            """INSERT INTO sermons
            (title, preacher, scripture, summary, content, category_id, thumbnail, audio_url, video_url, featured)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                request.form["title"],
                request.form["preacher"],
                request.form.get("scripture"),
                request.form.get("summary"),
                request.form.get("content"),
                request.form.get("category_id") or None,
                thumbnail or "",
                request.form.get("audio_url"),
                request.form.get("video_url"),
                1 if request.form.get("featured") else 0,
            ),
        )
        db.commit()
        flash("Sermon added.", "success")
        return redirect(url_for("admin_sermons"))
    sermons_rows = db.execute("SELECT sermons.*, categories.name AS category FROM sermons LEFT JOIN categories ON categories.id = sermons.category_id ORDER BY sermons.created_at DESC").fetchall()
    categories_rows = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    return render_template("admin_sermons.html", sermons=sermons_rows, categories=categories_rows)


@app.route("/admin/sermon/<int:item_id>/delete", methods=["POST"])
@admin_required
def delete_sermon(item_id):
    db = get_db()
    db.execute("DELETE FROM sermons WHERE id = ?", (item_id,))
    db.commit()
    flash("Sermon deleted.", "success")
    return redirect(url_for("admin_sermons"))


@app.route("/admin/devotionals", methods=["GET", "POST"])
@admin_required
def admin_devotionals():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO devotionals (title, scripture, content, category_id) VALUES (?, ?, ?, ?)",
            (request.form["title"], request.form.get("scripture"), request.form["content"], request.form.get("category_id") or None),
        )
        db.commit()
        flash("Devotional added.", "success")
        return redirect(url_for("admin_devotionals"))
    rows = db.execute("SELECT devotionals.*, categories.name AS category FROM devotionals LEFT JOIN categories ON categories.id = devotionals.category_id ORDER BY devotionals.created_at DESC").fetchall()
    categories_rows = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    return render_template("admin_devotionals.html", devotionals=rows, categories=categories_rows)


@app.route("/admin/devotional/<int:item_id>/delete", methods=["POST"])
@admin_required
def delete_devotional(item_id):
    db = get_db()
    db.execute("DELETE FROM devotionals WHERE id = ?", (item_id,))
    db.commit()
    flash("Devotional deleted.", "success")
    return redirect(url_for("admin_devotionals"))


@app.route("/admin/events", methods=["GET", "POST"])
@admin_required
def admin_events():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO events (title, event_date, location, description, event_type) VALUES (?, ?, ?, ?, ?)",
            (request.form["title"], request.form["event_date"], request.form.get("location"), request.form.get("description"), request.form.get("event_type")),
        )
        db.commit()
        flash("Event added.", "success")
        return redirect(url_for("admin_events"))
    rows = db.execute("SELECT * FROM events ORDER BY event_date ASC").fetchall()
    return render_template("admin_events.html", events=rows)


@app.route("/admin/event/<int:item_id>/delete", methods=["POST"])
@admin_required
def delete_event(item_id):
    db = get_db()
    db.execute("DELETE FROM events WHERE id = ?", (item_id,))
    db.commit()
    flash("Event deleted.", "success")
    return redirect(url_for("admin_events"))


@app.route("/admin/categories", methods=["GET", "POST"])
@admin_required
def admin_categories():
    db = get_db()
    if request.method == "POST":
        try:
            db.execute(
                "INSERT INTO categories (name, description) VALUES (?, ?)",
                (request.form["name"], request.form.get("description")),
            )
            db.commit()
            flash("Category added.", "success")
        except sqlite3.IntegrityError:
            flash("Category already exists.", "error")
        return redirect(url_for("admin_categories"))
    rows = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    return render_template("admin_categories.html", categories=rows)


@app.route("/admin/category/<int:item_id>/delete", methods=["POST"])
@admin_required
def delete_category(item_id):
    db = get_db()
    db.execute("DELETE FROM categories WHERE id = ?", (item_id,))
    db.commit()
    flash("Category deleted.", "success")
    return redirect(url_for("admin_categories"))


@app.route("/admin/gallery", methods=["GET", "POST"])
@admin_required
def admin_gallery():
    db = get_db()
    if request.method == "POST":
        image_path = save_upload(request.files.get("image"), "gallery")
        if image_path:
            db.execute("INSERT INTO gallery (title, image_path) VALUES (?, ?)", (request.form["title"], image_path))
            db.commit()
            flash("Gallery image uploaded.", "success")
        return redirect(url_for("admin_gallery"))
    rows = db.execute("SELECT * FROM gallery ORDER BY created_at DESC").fetchall()
    return render_template("admin_gallery.html", gallery=rows)


@app.context_processor
def inject_globals():
    verse = {
        "reference": "Matthew 5:14",
        "text": "You are the light of the world. A city set on a hill cannot be hidden.",
    }
    return {"verse_of_day": verse, "current_year": datetime.utcnow().year}


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


def export_sample_csvs():
    sermons_path = os.path.join(BASE_DIR, "sample_sermons.csv")
    studies_path = os.path.join(BASE_DIR, "sample_bible_studies.csv")
    if not os.path.exists(sermons_path):
        with open(sermons_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["title", "preacher", "scripture", "category", "summary"])
            writer.writerow(["Walking in the Light", "Pastor Daniel Mensah", "John 8:12", "Faith", "Jesus is the light that guides every believer."])
            writer.writerow(["The Power of Midnight Prayer", "Pastor Daniel Mensah", "Acts 16:25-26", "Prayer", "Prayer opens prison doors and renews faith."])
    if not os.path.exists(studies_path):
        with open(studies_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["title", "teacher", "scripture", "meeting_time", "description"])
            writer.writerow(["Foundations of Faith", "Elder Miriam Cole", "Hebrews 11", "Wednesdays, 6:30 PM", "A weekly study on faith and obedience."])
            writer.writerow(["The Life of Christ", "Pastor Daniel Mensah", "Luke 1-24", "Saturdays, 10:00 AM", "A journey through the ministry of Jesus."])


if not os.path.exists(DATABASE):
    init_db(seed=True)
    export_sample_csvs()


if __name__ == "__main__":
    init_db(seed=True)
    export_sample_csvs()
    app.run(debug=True)
