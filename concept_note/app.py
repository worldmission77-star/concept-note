import os
import sqlite3
import uuid
from datetime import date

from flask import Flask, g, render_template, request, redirect, url_for, session, flash, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR lets you point the DB + uploads at a persistent disk in production
# (e.g. Render: set DATA_DIR=/var/data and attach a persistent disk there).
# Locally it just defaults to the project folder.
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)
DATABASE = os.path.join(DATA_DIR, "concept_note.db")
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# Default admin account, seeded on first DB init. Change ADMIN_USERNAME /
# ADMIN_PASSWORD via environment variables before deploying, or change the
# password from inside the app right after your first login.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin1234")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        with open(os.path.join(BASE_DIR, "schema.sql"), "r", encoding="utf-8") as f:
            db.executescript(f.read())
        db.execute(
            """INSERT INTO users (username, password_hash, name, grade, is_admin)
               VALUES (?, ?, '관리자', '-', 1)""",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD)),
        )
        db.commit()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # Served through our own route (not Flask's static handler) so UPLOAD_FOLDER
    # can live on a separate persistent disk in production, outside static/.
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/")
def index():
    if session.get("user_id"):
        if session.get("is_admin"):
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("notes_list"))
    return redirect(url_for("login"))


# ---------- 로그인 ----------
# 학생 계정은 관리자만 생성할 수 있습니다 (아래 admin_student_new 참고).
# 자율 회원가입 페이지는 없습니다.

def validate_student_form(form, require_password=True):
    """공용 학생 계정 입력값 검증. (errors 리스트, 정제된 값 dict) 반환."""
    username = form.get("username", "").strip()
    password = form.get("password", "")
    password_confirm = form.get("password_confirm", "")
    name = form.get("name", "").strip()
    grade = form.get("grade", "").strip()
    student_phone = form.get("student_phone", "").strip()
    parent_phone = form.get("parent_phone", "").strip()

    errors = []
    if not username:
        errors.append("아이디를 입력해주세요.")
    if require_password:
        if not password:
            errors.append("비밀번호를 입력해주세요.")
        elif password != password_confirm:
            errors.append("비밀번호가 일치하지 않습니다.")
    if not name:
        errors.append("이름을 입력해주세요.")
    if not grade:
        errors.append("학년을 입력해주세요.")

    if not errors:
        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            errors.append("이미 사용 중인 아이디입니다.")

    values = {
        "username": username,
        "password": password,
        "name": name,
        "grade": grade,
        "student_phone": student_phone,
        "parent_phone": parent_phone,
    }
    return errors, values


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["is_admin"] = bool(user["is_admin"])
        if session["is_admin"]:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("notes_list"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def account_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        new_password_confirm = request.form.get("new_password_confirm", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()

        errors = []
        if not check_password_hash(user["password_hash"], current_password):
            errors.append("현재 비밀번호가 올바르지 않습니다.")
        if not new_password:
            errors.append("새 비밀번호를 입력해주세요.")
        elif new_password != new_password_confirm:
            errors.append("새 비밀번호가 일치하지 않습니다.")

        if errors:
            for e in errors:
                flash(e)
            return render_template("account_password.html")

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), session["user_id"]),
        )
        db.commit()
        flash("비밀번호가 변경되었습니다.")
        return redirect(url_for("index"))

    return render_template("account_password.html")


# ---------- 개념노트 목록 / 작성 / 수정 / 삭제 ----------

@app.route("/notes")
@login_required
def notes_list():
    db = get_db()
    notes = db.execute(
        """SELECT id, title, note_date, content, photo_filename, feedback,
                  checked_at, parent_checked_at
           FROM notes WHERE user_id = ?
           ORDER BY note_date DESC, id DESC""",
        (session["user_id"],),
    ).fetchall()
    return render_template("notes_list.html", notes=notes)


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def note_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        note_date = request.form.get("note_date", "").strip() or date.today().isoformat()
        content = request.form.get("content", "").strip()
        photo = request.files.get("photo")

        if not title:
            flash("제목을 입력해주세요.")
            return render_template("note_form.html", form=request.form, note=None)

        photo_filename = None
        if photo and photo.filename:
            if not allowed_file(photo.filename):
                flash("이미지 파일만 첨부할 수 있습니다 (png, jpg, jpeg, gif, webp).")
                return render_template("note_form.html", form=request.form, note=None)
            ext = photo.filename.rsplit(".", 1)[1].lower()
            photo_filename = f"{uuid.uuid4().hex}.{ext}"
            photo.save(os.path.join(app.config["UPLOAD_FOLDER"], photo_filename))

        db = get_db()
        db.execute(
            """INSERT INTO notes (user_id, title, note_date, content, photo_filename)
               VALUES (?, ?, ?, ?, ?)""",
            (session["user_id"], title, note_date, content, photo_filename),
        )
        db.commit()
        flash("노트가 저장되었습니다.")
        return redirect(url_for("notes_list"))

    return render_template("note_form.html", form={}, note=None, today=date.today().isoformat())


def get_owned_note_or_404(note_id):
    db = get_db()
    note = db.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"]),
    ).fetchone()
    if note is None:
        abort(404)
    return note


@app.route("/notes/<int:note_id>")
@login_required
def note_detail(note_id):
    note = get_owned_note_or_404(note_id)
    return render_template("note_detail.html", note=note)


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def note_edit(note_id):
    note = get_owned_note_or_404(note_id)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        note_date = request.form.get("note_date", "").strip() or note["note_date"]
        content = request.form.get("content", "").strip()
        photo = request.files.get("photo")
        remove_photo = request.form.get("remove_photo") == "1"

        if not title:
            flash("제목을 입력해주세요.")
            return render_template("note_form.html", form=request.form, note=note)

        db = get_db()
        photo_filename = note["photo_filename"]

        if remove_photo and photo_filename:
            old_path = os.path.join(app.config["UPLOAD_FOLDER"], photo_filename)
            if os.path.exists(old_path):
                os.remove(old_path)
            photo_filename = None

        if photo and photo.filename:
            if not allowed_file(photo.filename):
                flash("이미지 파일만 첨부할 수 있습니다 (png, jpg, jpeg, gif, webp).")
                return render_template("note_form.html", form=request.form, note=note)
            if photo_filename:
                old_path = os.path.join(app.config["UPLOAD_FOLDER"], photo_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)
            ext = photo.filename.rsplit(".", 1)[1].lower()
            photo_filename = f"{uuid.uuid4().hex}.{ext}"
            photo.save(os.path.join(app.config["UPLOAD_FOLDER"], photo_filename))

        db.execute(
            """UPDATE notes SET title = ?, note_date = ?, content = ?, photo_filename = ?
               WHERE id = ? AND user_id = ?""",
            (title, note_date, content, photo_filename, note_id, session["user_id"]),
        )
        db.commit()
        flash("노트가 수정되었습니다.")
        return redirect(url_for("note_detail", note_id=note_id))

    return render_template("note_form.html", form=dict(note), note=note)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def note_delete(note_id):
    note = get_owned_note_or_404(note_id)
    db = get_db()

    if note["photo_filename"]:
        path = os.path.join(app.config["UPLOAD_FOLDER"], note["photo_filename"])
        if os.path.exists(path):
            os.remove(path)

    db.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, session["user_id"]))
    db.commit()
    flash("노트가 삭제되었습니다.")
    return redirect(url_for("notes_list"))


# ---------- 관리자 페이지 ----------

@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()

    student_id = request.args.get("student_id", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    query = """
        SELECT notes.id, notes.title, notes.note_date, notes.content,
               notes.photo_filename, notes.feedback, notes.checked_at,
               notes.parent_checked_at,
               users.id AS student_id, users.name AS student_name, users.grade
        FROM notes
        JOIN users ON users.id = notes.user_id
        WHERE 1=1
    """
    params = []
    if student_id:
        query += " AND users.id = ?"
        params.append(student_id)
    if date_from:
        query += " AND notes.note_date >= ?"
        params.append(date_from)
    if date_to:
        query += " AND notes.note_date <= ?"
        params.append(date_to)
    query += " ORDER BY notes.note_date DESC, notes.id DESC"

    notes = db.execute(query, params).fetchall()
    students = db.execute(
        "SELECT id, name, grade FROM users WHERE is_admin = 0 ORDER BY name"
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        notes=notes,
        students=students,
        selected_student_id=student_id,
        date_from=date_from,
        date_to=date_to,
    )


@app.route("/admin/students")
@admin_required
def admin_students():
    db = get_db()
    students = db.execute(
        """SELECT id, username, name, grade, student_phone, parent_phone,
                  (SELECT COUNT(*) FROM notes WHERE notes.user_id = users.id) AS note_count
           FROM users WHERE is_admin = 0 ORDER BY name"""
    ).fetchall()
    return render_template("admin_students.html", students=students)


@app.route("/admin/students/new", methods=["GET", "POST"])
@admin_required
def admin_student_new():
    if request.method == "POST":
        errors, values = validate_student_form(request.form, require_password=True)

        if errors:
            for e in errors:
                flash(e)
            return render_template("admin_student_form.html", form=request.form)

        db = get_db()
        db.execute(
            """INSERT INTO users (username, password_hash, name, grade, student_phone, parent_phone)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                values["username"],
                generate_password_hash(values["password"]),
                values["name"],
                values["grade"],
                values["student_phone"],
                values["parent_phone"],
            ),
        )
        db.commit()
        flash(f"{values['name']} 학생 계정이 생성되었습니다. (아이디: {values['username']})")
        return redirect(url_for("admin_students"))

    return render_template("admin_student_form.html", form={})


@app.route("/admin/students/<int:student_id>/delete", methods=["POST"])
@admin_required
def admin_student_delete(student_id):
    db = get_db()
    student = db.execute(
        "SELECT * FROM users WHERE id = ? AND is_admin = 0", (student_id,)
    ).fetchone()
    if student is None:
        abort(404)

    notes = db.execute("SELECT photo_filename FROM notes WHERE user_id = ?", (student_id,)).fetchall()
    for note in notes:
        if note["photo_filename"]:
            path = os.path.join(app.config["UPLOAD_FOLDER"], note["photo_filename"])
            if os.path.exists(path):
                os.remove(path)

    db.execute("DELETE FROM notes WHERE user_id = ?", (student_id,))
    db.execute("DELETE FROM users WHERE id = ?", (student_id,))
    db.commit()
    flash(f"{student['name']} 학생 계정과 노트가 삭제되었습니다.")
    return redirect(url_for("admin_students"))


DEFAULT_RESET_PASSWORD = "1111"


@app.route("/admin/students/<int:student_id>/reset-password", methods=["POST"])
@admin_required
def admin_student_reset_password(student_id):
    db = get_db()
    student = db.execute(
        "SELECT * FROM users WHERE id = ? AND is_admin = 0", (student_id,)
    ).fetchone()
    if student is None:
        abort(404)

    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(DEFAULT_RESET_PASSWORD), student_id),
    )
    db.commit()
    flash(f"{student['name']} 학생의 비밀번호가 '{DEFAULT_RESET_PASSWORD}'로 초기화되었습니다.")
    return redirect(url_for("admin_students"))


def get_any_note_or_404(note_id):
    db = get_db()
    note = db.execute(
        """SELECT notes.*, users.name AS student_name, users.grade
           FROM notes JOIN users ON users.id = notes.user_id
           WHERE notes.id = ?""",
        (note_id,),
    ).fetchone()
    if note is None:
        abort(404)
    return note


@app.route("/admin/notes/<int:note_id>")
@admin_required
def admin_note_detail(note_id):
    note = get_any_note_or_404(note_id)

    if not note["parent_token"]:
        db = get_db()
        db.execute(
            "UPDATE notes SET parent_token = ? WHERE id = ?",
            (uuid.uuid4().hex, note_id),
        )
        db.commit()
        note = get_any_note_or_404(note_id)

    parent_url = request.host_url.rstrip("/") + url_for("parent_note_view", token=note["parent_token"])
    try:
        d = date.fromisoformat(note["note_date"])
        note_date_kr = f"{d.year}년 {d.month}월 {d.day}일"
    except (ValueError, TypeError):
        note_date_kr = note["note_date"]
    parent_message = f"{note['student_name']} 학생의 {note_date_kr} 개념노트입니다. 확인 부탁드립니다.\n{parent_url}"
    return render_template(
        "admin_note_detail.html", note=note, parent_url=parent_url, parent_message=parent_message
    )


@app.route("/admin/notes/<int:note_id>/regenerate-link", methods=["POST"])
@admin_required
def admin_note_regenerate_link(note_id):
    note = get_any_note_or_404(note_id)
    db = get_db()
    db.execute(
        "UPDATE notes SET parent_token = ? WHERE id = ?",
        (uuid.uuid4().hex, note_id),
    )
    db.commit()
    flash("새 학부모 링크가 생성되었습니다. 이전 링크는 더 이상 사용할 수 없습니다.")
    return redirect(url_for("admin_note_detail", note_id=note_id))


@app.route("/admin/notes/<int:note_id>/feedback", methods=["POST"])
@admin_required
def admin_note_feedback(note_id):
    note = get_any_note_or_404(note_id)
    feedback = request.form.get("feedback", "").strip()

    db = get_db()
    db.execute(
        "UPDATE notes SET feedback = ?, checked_at = CURRENT_TIMESTAMP WHERE id = ?",
        (feedback, note_id),
    )
    db.commit()
    flash("확인 및 코멘트가 저장되었습니다.")
    return redirect(url_for("admin_note_detail", note_id=note_id))


@app.route("/admin/notes/<int:note_id>/delete", methods=["POST"])
@admin_required
def admin_note_delete(note_id):
    note = get_any_note_or_404(note_id)
    db = get_db()

    if note["photo_filename"]:
        path = os.path.join(app.config["UPLOAD_FOLDER"], note["photo_filename"])
        if os.path.exists(path):
            os.remove(path)

    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    flash("노트가 삭제되었습니다.")
    return redirect(url_for("admin_dashboard"))


# ---------- 학부모 확인 페이지 (로그인 불필요, 토큰 기반) ----------

def get_note_by_parent_token_or_404(token):
    db = get_db()
    note = db.execute(
        """SELECT notes.*, users.name AS student_name, users.grade
           FROM notes JOIN users ON users.id = notes.user_id
           WHERE notes.parent_token = ?""",
        (token,),
    ).fetchone()
    if note is None:
        abort(404)
    return note


@app.route("/p/<token>")
def parent_note_view(token):
    note = get_note_by_parent_token_or_404(token)
    return render_template("parent_note.html", note=note)


@app.route("/p/<token>/confirm", methods=["POST"])
def parent_note_confirm(token):
    note = get_note_by_parent_token_or_404(token)
    if not note["parent_checked_at"]:
        db = get_db()
        db.execute(
            "UPDATE notes SET parent_checked_at = CURRENT_TIMESTAMP WHERE id = ?",
            (note["id"],),
        )
        db.commit()
    return redirect(url_for("parent_note_view", token=token))


# Ensure the DB exists whether run via `python app.py` (dev) or a WSGI
# server like gunicorn (production, e.g. Render) importing this module.
if not os.path.exists(DATABASE):
    init_db()
    print("데이터베이스를 초기화했습니다.")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug, host="0.0.0.0", port=port)
