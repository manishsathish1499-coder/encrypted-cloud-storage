import os
import sqlite3
from datetime import datetime
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash

from crypto_utils import (
    generate_rsa_keys,
    encrypt_file_aes,
    decrypt_file_aes,
    encrypt_key_rsa,
    decrypt_key_rsa
)

app = Flask(__name__)
app.secret_key = "super_secret_key"

BASE_DIR = "user_data"
os.makedirs(BASE_DIR, exist_ok=True)

# Generate RSA keys once
generate_rsa_keys()


# ==========================
# DATABASE SETUP
# ==========================
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ==========================
# REGISTER
# ==========================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            conn.commit()
            conn.close()

            # Create user folders
            user_path = os.path.join(BASE_DIR, username)
            os.makedirs(os.path.join(user_path, "uploads"), exist_ok=True)
            os.makedirs(os.path.join(user_path, "encrypted_files"), exist_ok=True)
            os.makedirs(os.path.join(user_path, "decrypted_files"), exist_ok=True)

            return redirect(url_for("login"))

        except:
            return "Username already exists!"

    return render_template("register.html")


# ==========================
# LOGIN
# ==========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            session["user"] = username
            return redirect(url_for("home"))
        else:
            return "Invalid username or password"

    return render_template("login.html")


# ==========================
# LOGOUT
# ==========================
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ==========================
# HOME (Dashboard)
# ==========================
@app.route("/")
def home():
    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]
    user_path = os.path.join(BASE_DIR, username)
    encrypted_folder = os.path.join(user_path, "encrypted_files")

    file_data = []
    total_size = 0

    for file in os.listdir(encrypted_folder):
        if file.endswith(".enc"):
            full_path = os.path.join(encrypted_folder, file)
            size = os.path.getsize(full_path)
            total_size += size

            size_kb = round(size / 1024, 2)
            modified_time = os.path.getmtime(full_path)
            formatted_time = datetime.fromtimestamp(
                modified_time
            ).strftime("%Y-%m-%d %H:%M")

            file_data.append({
                "name": file,
                "size": size_kb,
                "time": formatted_time
            })

    total_size_mb = round(total_size / (1024 * 1024), 2)

    return render_template(
        "index.html",
        files=file_data,
        user=username,
        total_files=len(file_data),
        total_size=total_size_mb
    )


# ==========================
# UPLOAD WITH 10MB LIMIT
# ==========================
@app.route("/upload", methods=["POST"])
def upload_file():
    if "user" not in session:
        return redirect(url_for("login"))

    file = request.files.get("file")

    if not file or file.filename == "":
        return redirect(url_for("home"))

    if file.filename.endswith(".enc"):
        return "You cannot upload already encrypted (.enc) files!"

    username = session["user"]
    user_path = os.path.join(BASE_DIR, username)
    encrypted_folder = os.path.join(user_path, "encrypted_files")

    MAX_STORAGE_MB = 10
    current_size = 0

    for f in os.listdir(encrypted_folder):
        if f.endswith(".enc"):
            current_size += os.path.getsize(
                os.path.join(encrypted_folder, f)
            )

    uploaded_size = len(file.read())
    file.seek(0)

    total_after_upload = current_size + uploaded_size
    total_after_upload_mb = total_after_upload / (1024 * 1024)

    if total_after_upload_mb > MAX_STORAGE_MB:
        return "Storage limit exceeded! (10 MB max)"

    upload_path = os.path.join(user_path, "uploads", file.filename)
    file.save(upload_path)

    encrypted_path, aes_key = encrypt_file_aes(upload_path)
    encrypted_key = encrypt_key_rsa(aes_key)

    final_path = os.path.join(
        encrypted_folder,
        os.path.basename(encrypted_path)
    )

    key_path = final_path + ".key"

    os.replace(encrypted_path, final_path)

    if os.path.exists(upload_path):
        os.remove(upload_path)

    with open(key_path, "wb") as f:
        f.write(encrypted_key)

    return redirect(url_for("home"))


# ==========================
# DOWNLOAD ENCRYPTED
# ==========================
@app.route("/download/<filename>")
def download(filename):
    username = session["user"]
    encrypted_folder = os.path.join(BASE_DIR, username, "encrypted_files")

    return send_from_directory(
        directory=encrypted_folder,
        path=filename,
        as_attachment=True
    )


# ==========================
# DECRYPT & DOWNLOAD
# ==========================
@app.route("/decrypt/<filename>")
def decrypt(filename):
    username = session["user"]
    user_path = os.path.join(BASE_DIR, username)

    encrypted_path = os.path.join(user_path, "encrypted_files", filename)
    key_path = encrypted_path + ".key"

    with open(key_path, "rb") as f:
        encrypted_key = f.read()

    aes_key = decrypt_key_rsa(encrypted_key)
    decrypted_file_path = decrypt_file_aes(encrypted_path, aes_key)

    return send_from_directory(
        directory=os.path.join(user_path, "decrypted_files"),
        path=os.path.basename(decrypted_file_path),
        as_attachment=True
    )


# ==========================
# DELETE FILE
# ==========================
@app.route("/delete/<filename>")
def delete(filename):
    username = session["user"]
    encrypted_folder = os.path.join(BASE_DIR, username, "encrypted_files")

    encrypted_path = os.path.join(encrypted_folder, filename)
    key_path = encrypted_path + ".key"

    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    if os.path.exists(key_path):
        os.remove(key_path)

    return redirect(url_for("home"))


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)