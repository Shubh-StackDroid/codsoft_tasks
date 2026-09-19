from flask import (
    Flask, request, redirect, url_for,
    session, send_file, render_template_string
)
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

from pathlib import Path
from functools import wraps
import sqlite3
import secrets
import time
import os


# =========================================================
# APPLICATION SETUP
# =========================================================

app = Flask(__name__)

# In a real application, keep this secret outside the source code.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32)
)

DATABASE = "file_sharing.db"

UPLOAD_FOLDER = Path("encrypted_files")
UPLOAD_FOLDER.mkdir(exist_ok=True)


# =========================================================
# ENCRYPTION KEY
# =========================================================

KEY_FILE = Path("encryption.key")

if not KEY_FILE.exists():
    KEY_FILE.write_bytes(Fernet.generate_key())

fernet = Fernet(KEY_FILE.read_bytes())


# =========================================================
# DATABASE
# =========================================================

def get_db():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


def create_database():

    db = get_db()

    # Users table
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            role TEXT NOT NULL DEFAULT 'user'

        )
    """)

    # Files table
    db.execute("""
        CREATE TABLE IF NOT EXISTS files (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            filename TEXT NOT NULL,

            stored_name TEXT NOT NULL,

            owner_id INTEGER NOT NULL,

            uploaded_at INTEGER NOT NULL

        )
    """)

    # Temporary download links
    db.execute("""
        CREATE TABLE IF NOT EXISTS download_links (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            token TEXT UNIQUE NOT NULL,

            file_id INTEGER NOT NULL,

            expires_at INTEGER NOT NULL

        )
    """)

    db.commit()

    db.close()


# =========================================================
# LOGIN REQUIRED DECORATOR
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# =========================================================
# HTML TEMPLATE
# =========================================================

PAGE = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>Secure File Sharing</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family: Arial, sans-serif;

    background: #07111f;

    color: white;

}

.container {

    width: 90%;

    max-width: 1000px;

    margin: 50px auto;

}

.card {

    background: #111f33;

    padding: 30px;

    margin-bottom: 25px;

    border-radius: 18px;

    box-shadow: 0 10px 30px rgba(0,0,0,.35);

}

h1 {

    color: #55c8ff;

}

h2 {

    color: #72d7ff;

}

input {

    width: 100%;

    padding: 14px;

    margin: 8px 0;

    border-radius: 8px;

    border: none;

}

button {

    width: 100%;

    padding: 14px;

    margin-top: 10px;

    border: none;

    border-radius: 8px;

    background: #1597d3;

    color: white;

    font-size: 16px;

    font-weight: bold;

    cursor: pointer;

}

button:hover {

    background: #20b0ee;

}

a {

    color: #5fd5ff;

    text-decoration: none;

}

.file {

    background: #192c44;

    padding: 18px;

    margin: 12px 0;

    border-radius: 12px;

}

.success {

    color: #66e49b;

}

.error {

    color: #ff7272;

}

.info {

    color: #72d7ff;

}

.badge {

    display: inline-block;

    background: #1d4563;

    padding: 7px 12px;

    border-radius: 20px;

}

.small {

    font-size: 14px;

    color: #aebdcd;

}

</style>

</head>


<body>

<div class="container">

{{ content | safe }}

</div>

</body>

</html>

"""


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    message = ""

    if request.method == "POST":

        username = request.form["username"].strip()

        password = request.form["password"]

        confirm = request.form["confirm"]


        if len(username) < 3:

            message = "Username must have at least 3 characters."

        elif len(password) < 8:

            message = "Password must have at least 8 characters."

        elif password != confirm:

            message = "Passwords do not match."

        else:

            db = get_db()

            try:

                hashed_password = generate_password_hash(password)

                db.execute("""
                    INSERT INTO users
                    (username, password, role)
                    VALUES (?, ?, ?)
                """, (
                    username,
                    hashed_password,
                    "user"
                ))

                db.commit()

                db.close()

                return redirect(url_for("login"))

            except sqlite3.IntegrityError:

                db.close()

                message = "Username already exists."


    content = f"""

    <div class="card">

        <h1>📝 Create Account</h1>

        <p class="error">{message}</p>

        <form method="POST">

            <input
                type="text"
                name="username"
                placeholder="Choose username"
                required
            >

            <input
                type="password"
                name="password"
                placeholder="Choose password"
                required
            >

            <input
                type="password"
                name="confirm"
                placeholder="Confirm password"
                required
            >

            <button type="submit">
                Create Account
            </button>

        </form>

        <br>

        <a href="/">
            Already have an account? Login
        </a>

    </div>

    """

    return render_template_string(
        PAGE,
        content=content
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/", methods=["GET", "POST"])
def login():

    if "user_id" in session:

        return redirect(url_for("dashboard"))

    message = ""

    if request.method == "POST":

        username = request.form["username"].strip()

        password = request.form["password"]

        db = get_db()

        user = db.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        db.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]

            session["username"] = user["username"]

            session["role"] = user["role"]

            return redirect(url_for("dashboard"))

        message = "Invalid username or password."


    content = f"""

    <div class="card">

        <h1>🔐 Secure File Sharing</h1>

        <h2>Login</h2>

        <p class="error">{message}</p>

        <form method="POST">

            <input
                type="text"
                name="username"
                placeholder="Username"
                required
            >

            <input
                type="password"
                name="password"
                placeholder="Password"
                required
            >

            <button type="submit">
                Login
            </button>

        </form>

        <br>

        <a href="/register">
            Create a new account
        </a>

    </div>

    """

    return render_template_string(
        PAGE,
        content=content
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()

    files = db.execute("""
        SELECT *
        FROM files
        WHERE owner_id = ?
        ORDER BY uploaded_at DESC
    """, (
        session["user_id"],
    )).fetchall()

    db.close()

    files_html = ""

    for file in files:

        files_html += f"""

        <div class="file">

            📄 <b>{file["filename"]}</b>

            <br><br>

            <a href="/download/{file["id"]}">
                ⬇ Download
            </a>

            &nbsp;&nbsp;

            <a href="/create-link/{file["id"]}">
                🔗 Create Temporary Link
            </a>

        </div>

        """


    content = f"""

    <div class="card">

        <h1>🔐 Secure File Sharing</h1>

        <p>
            Welcome,
            <b>{session["username"]}</b>
        </p>

        <span class="badge">
            Role: {session["role"]}
        </span>

        <br><br>

        <a href="/logout">
            Logout
        </a>

    </div>


    <div class="card">

        <h2>📤 Upload File</h2>

        <form
            method="POST"
            action="/upload"
            enctype="multipart/form-data"
        >

            <input
                type="file"
                name="file"
                required
            >

            <button type="submit">
                🔒 Encrypt & Upload
            </button>

        </form>

        <p class="small">
            Files are encrypted before being stored.
        </p>

    </div>


    <div class="card">

        <h2>📁 My Files</h2>

        {
            files_html
            if files_html
            else
            "<p>No files uploaded yet.</p>"
        }

    </div>

    """


    return render_template_string(
        PAGE,
        content=content
    )


# =========================================================
# UPLOAD
# =========================================================

@app.route("/upload", methods=["POST"])
@login_required
def upload():

    file = request.files.get("file")

    if not file or file.filename == "":

        return "No file selected."


    # Prevent path traversal attacks
    original_name = Path(file.filename).name


    # Read file
    data = file.read()


    # Encrypt before storing
    encrypted_data = fernet.encrypt(data)


    # Random storage name
    stored_name = secrets.token_hex(32)


    file_path = UPLOAD_FOLDER / stored_name

    file_path.write_bytes(encrypted_data)


    db = get_db()

    db.execute("""
        INSERT INTO files
        (
            filename,
            stored_name,
            owner_id,
            uploaded_at
        )

        VALUES (?, ?, ?, ?)

    """, (
        original_name,
        stored_name,
        session["user_id"],
        int(time.time())
    ))

    db.commit()

    db.close()


    return redirect(url_for("dashboard"))


# =========================================================
# NORMAL DOWNLOAD
# =========================================================

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):

    db = get_db()

    file = db.execute("""
        SELECT *
        FROM files
        WHERE id = ?
    """, (file_id,)).fetchone()

    db.close()


    if not file:

        return "File not found.", 404


    # Role-based access control
    if (
        file["owner_id"] != session["user_id"]
        and session["role"] != "admin"
    ):

        return "Access denied.", 403


    file_path = UPLOAD_FOLDER / file["stored_name"]


    if not file_path.exists():

        return "File not found.", 404


    # Decrypt
    encrypted_data = file_path.read_bytes()

    try:

        decrypted_data = fernet.decrypt(
            encrypted_data
        )

    except Exception:

        return "Unable to decrypt file.", 500


    # Create temporary decrypted file
    temp_file = (
        UPLOAD_FOLDER /
        ("temp_" + secrets.token_hex(16))
    )

    temp_file.write_bytes(decrypted_data)


    response = send_file(
        temp_file,
        as_attachment=True,
        download_name=file["filename"]
    )


    @response.call_on_close
    def remove_temp_file():

        try:

            temp_file.unlink()

        except FileNotFoundError:

            pass


    return response


# =========================================================
# CREATE TEMPORARY DOWNLOAD LINK
# =========================================================

@app.route("/create-link/<int:file_id>")
@login_required
def create_link(file_id):

    db = get_db()

    file = db.execute("""
        SELECT *
        FROM files
        WHERE id = ?
    """, (file_id,)).fetchone()


    if not file:

        db.close()

        return "File not found.", 404


    # Only owner or admin can create a link
    if (
        file["owner_id"] != session["user_id"]
        and session["role"] != "admin"
    ):

        db.close()

        return "Access denied.", 403


    # Link valid for 5 minutes
    expiration = int(time.time()) + 300


    token = secrets.token_urlsafe(32)


    db.execute("""
        INSERT INTO download_links
        (
            token,
            file_id,
            expires_at
        )

        VALUES (?, ?, ?)

    """, (
        token,
        file_id,
        expiration
    ))


    db.commit()

    db.close()


    link = url_for(
        "temporary_download",
        token=token,
        _external=True
    )


    content = f"""

    <div class="card">

        <h1>🔗 Temporary Download Link</h1>

        <p class="success">
            Link created successfully!
        </p>

        <p>
            This link will expire in
            <b>5 minutes</b>.
        </p>

        <input
            value="{link}"
            readonly
            onclick="this.select()"
        >

        <p class="small">
            Copy this link and share it with the intended recipient.
        </p>

        <br>

        <a href="/dashboard">
            ← Back to Dashboard
        </a>

    </div>

    """


    return render_template_string(
        PAGE,
        content=content
    )


# =========================================================
# TEMPORARY DOWNLOAD
# =========================================================

@app.route("/temporary-download/<token>")
def temporary_download(token):

    db = get_db()


    link = db.execute("""
        SELECT *
        FROM download_links
        WHERE token = ?
    """, (token,)).fetchone()


    if not link:

        db.close()

        return "Invalid download link.", 404


    # Check expiration
    if int(time.time()) > link["expires_at"]:

        db.execute("""
            DELETE FROM download_links
            WHERE token = ?
        """, (token,))

        db.commit()

        db.close()

        return "This download link has expired.", 410


    file = db.execute("""
        SELECT *
        FROM files
        WHERE id = ?
    """, (link["file_id"],)).fetchone()


    if not file:

        db.close()

        return "File not found.", 404


    file_path = UPLOAD_FOLDER / file["stored_name"]


    if not file_path.exists():

        db.close()

        return "File not found.", 404


    encrypted_data = file_path.read_bytes()


    try:

        decrypted_data = fernet.decrypt(
            encrypted_data
        )

    except Exception:

        db.close()

        return "Unable to decrypt file.", 500


    temp_file = (
        UPLOAD_FOLDER /
        ("temp_" + secrets.token_hex(16))
    )


    temp_file.write_bytes(decrypted_data)


    # Delete link after use
    db.execute("""
        DELETE FROM download_links
        WHERE token = ?
    """, (token,))

    db.commit()

    db.close()


    response = send_file(
        temp_file,
        as_attachment=True,
        download_name=file["filename"]
    )


    @response.call_on_close
    def remove_temp_file():

        try:

            temp_file.unlink()

        except FileNotFoundError:

            pass


    return response


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    create_database()

    print("--------------------------------------")
    print("     SECURE FILE SHARING APP")
    print("--------------------------------------")
    print("Open: http://127.0.0.1:5000")
    print("--------------------------------------")

    app.run(debug=True)