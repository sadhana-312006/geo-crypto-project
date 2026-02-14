from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import datetime, timedelta
import base64, os, io

app = Flask(__name__)
CORS(app)

# ================= CONFIG =================

TIME_WINDOW_MINUTES = 60       # ⬅ increased
LOCATION_TOLERANCE = 0.01     # ⬅ ~1km tolerance

# ================= HELPERS =================

def get_time_window(dt):
    minute_block = (dt.minute // TIME_WINDOW_MINUTES) * TIME_WINDOW_MINUTES
    return dt.replace(minute=minute_block, second=0, microsecond=0)

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

def close(a, b):
    return abs(float(a) - float(b)) <= LOCATION_TOLERANCE

# ================= ROUTES =================

@app.route("/")
def home():
    return "Backend running"

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    try:
        file = request.files["file"]
        lat = request.form["lat"]
        lon = request.form["lon"]
        shared_secret = request.form["master_secret"]
    except:
        return jsonify({"error": "Missing data"}), 400

    now = datetime.utcnow()
    window = get_time_window(now)

    key = derive_key(shared_secret, lat, lon, window)
    encrypted = encrypt_bytes(file.read(), key)

    metadata = f"{lat},{lon},{window.isoformat()}|".encode()
    final_data = metadata + encrypted

    return send_file(
        io.BytesIO(final_data),
        as_attachment=True,
        download_name=file.filename + ".enc"
    )

@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    try:
        file = request.files["file"]
        cur_lat = request.form["lat"]
        cur_lon = request.form["lon"]
        shared_secret = request.form["master_secret"]
    except:
        return jsonify({"error": "Missing data"}), 400

    full_data = file.read()

    try:
        meta, encrypted = full_data.split(b"|", 1)
        saved_lat, saved_lon, time_str = meta.decode().split(",")
        saved_time = datetime.fromisoformat(time_str)
    except:
        return jsonify({"error": "Invalid encrypted file"}), 400

    # ---- LOCATION CHECK ----
    if not close(cur_lat, saved_lat) or not close(cur_lon, saved_lon):
        return jsonify({"error": "Location mismatch"}), 403

    # ---- TIME CHECK ----
    now = datetime.utcnow()
    if abs((now - saved_time).total_seconds()) > TIME_WINDOW_MINUTES * 60:
        return jsonify({"error": "Time window expired"}), 403

    # ---- KEY CHECK ----
    try:
        key = derive_key(shared_secret, saved_lat, saved_lon, saved_time)
        decrypted = decrypt_bytes(encrypted, key)
    except Exception as e:
        return jsonify({"error": "Key mismatch (DH secret incorrect)"}), 403

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=file.filename.replace(".enc", "")
    )

if __name__ == "__main__":
    app.run()
