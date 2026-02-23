from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import datetime
import base64, os, io, secrets, hashlib, smtplib, math
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# ================= HELPERS =================

def derive_key(shared_secret_b64, lat, lon, time_window):
    secret = base64.b64decode(shared_secret_b64)
    info = f"{lat}:{lon}:{time_window.isoformat()}".encode()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return hkdf.derive(secret)

def encrypt_bytes(data, key):
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    return nonce + cipher.encrypt(nonce, data, None)

def decrypt_bytes(data, key):
    cipher = ChaCha20Poly1305(key)
    nonce = data[:12]
    return cipher.decrypt(nonce, data[12:], None)

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dLat = math.radians(float(lat2) - float(lat1))
    dLon = math.radians(float(lon2) - float(lon1))
    a = math.sin(dLat/2)**2 + \
        math.cos(math.radians(float(lat1))) * \
        math.cos(math.radians(float(lat2))) * \
        math.sin(dLon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def send_email(receiver, subject, content):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = receiver
    msg.set_content(content)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_USER, EMAIL_PASS)
        smtp.send_message(msg)

# ================= ROUTES =================

@app.route("/")
def home():
    return "Backend running"

# 🔑 SEND PUBLIC KEY EARLY
@app.route("/send-key", methods=["POST"])
def send_key():
    email = request.form.get("email")
    public_key = request.form.get("public_key")

    if not email or not public_key:
        return jsonify({"error": "Missing email or public key"}), 400

    send_email(
        email,
        "SecureGeoCrypt - Public Key",
        f"Sender Public Key:\n\n{public_key}"
    )

    return jsonify({"message": "Public key sent successfully"})

# 🔐 ENCRYPT
@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    try:
        file = request.files["file"]
        lat = request.form["lat"]
        lon = request.form["lon"]
        shared_secret = request.form["master_secret"]
        time_limit = int(request.form["time_limit"])
        radius = float(request.form["radius"])
        email = request.form["email"]
    except:
        return jsonify({"error": "Missing required encryption data"}), 400

    now = datetime.utcnow()
    key = derive_key(shared_secret, lat, lon, now)
    encrypted = encrypt_bytes(file.read(), key)

    override_secret = secrets.token_hex(4)
    override_hash = hashlib.sha256(override_secret.encode()).hexdigest()

    metadata = f"{lat},{lon},{now.isoformat()},{time_limit},{radius},{override_hash}|".encode()
    final_data = metadata + encrypted

    send_email(
        email,
        "SecureGeoCrypt - Override Secret",
        f"Override Secret (use only if time expired):\n\n{override_secret}"
    )

    return send_file(
        io.BytesIO(final_data),
        as_attachment=True,
        download_name=file.filename + ".enc"
    )

# 🔓 DECRYPT
@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    try:
        file = request.files["file"]
        cur_lat = request.form["lat"]
        cur_lon = request.form["lon"]
        shared_secret = request.form["master_secret"]
        override_secret = request.form.get("override_secret")
    except:
        return jsonify({"error": "Missing required decryption data"}), 400

    full_data = file.read()

    try:
        meta, encrypted = full_data.split(b"|", 1)
        saved_lat, saved_lon, time_str, time_limit, radius, override_hash = meta.decode().split(",")
        saved_time = datetime.fromisoformat(time_str)
    except:
        return jsonify({"error": "Invalid encrypted file format"}), 400

    # LOCATION CHECK
    if float(radius) != 0:
        distance = haversine(cur_lat, cur_lon, saved_lat, saved_lon)
        if distance > float(radius):
            return jsonify({"error": "Access denied: Outside allowed radius"}), 403

    # TIME CHECK
    now = datetime.utcnow()
    expired = abs((now - saved_time).total_seconds()) > int(time_limit) * 60

    if expired:
        if not override_secret:
            return jsonify({"error": "Time expired: Enter override secret"}), 403
        if hashlib.sha256(override_secret.encode()).hexdigest() != override_hash:
            return jsonify({"error": "Invalid override secret"}), 403

    # KEY CHECK
    try:
        key = derive_key(shared_secret, saved_lat, saved_lon, saved_time)
        decrypted = decrypt_bytes(encrypted, key)
    except:
        return jsonify({"error": "Key mismatch: Incorrect shared secret"}), 403

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=file.filename.replace(".enc", "")
    )

if __name__ == "__main__":
    app.run()