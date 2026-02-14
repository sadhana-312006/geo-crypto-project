from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import datetime, timedelta
import os
import io

app = Flask(__name__)
CORS(app)

# ================= CONFIG =================

TIME_WINDOW_MINUTES = 5
LOCATION_TOLERANCE = 0.1  # approx 100 meters

# ================= HELPERS =================

def get_time_window(dt):
    minute_block = (dt.minute // TIME_WINDOW_MINUTES) * TIME_WINDOW_MINUTES
    return dt.replace(minute=minute_block, second=0, microsecond=0)

def derive_key(secret, lat, lon, time_window):
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
    encrypted = cipher.encrypt(nonce, data, None)
    return nonce + encrypted

def decrypt_bytes(data, key):
    cipher = ChaCha20Poly1305(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return cipher.decrypt(nonce, ciphertext, None)

def close(a, b):
    return abs(a - b) <= LOCATION_TOLERANCE

# ================= ROUTES =================

@app.route("/")
def home():
    return "Backend running"

# ================= ENCRYPT =================

@app.route("/encrypt", methods=["POST"])
def encrypt_file():

    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    lat = request.form.get("lat")
    lon = request.form.get("lon")
    shared_secret = request.form.get("master_secret")

    if not lat or not lon:
        return jsonify({"error": "Location required"}), 400

    if not shared_secret:
        return jsonify({"error": "Missing shared secret"}), 400

    MASTER_SECRET = shared_secret.encode()

    file = request.files["file"]
    data = file.read()

    now = datetime.utcnow()
    window = get_time_window(now)

    # Derive geo-temporal key using DH shared secret
    key = derive_key(MASTER_SECRET, lat, lon, window)
    encrypted = encrypt_bytes(data, key)

    # Store metadata in file
    metadata = f"{lat},{lon},{window.isoformat()}|".encode()
    final_data = metadata + encrypted

    return send_file(
        io.BytesIO(final_data),
        as_attachment=True,
        download_name=file.filename + ".enc"
    )

# ================= DECRYPT =================

@app.route("/decrypt", methods=["POST"])
def decrypt_file():

    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    cur_lat = float(request.form.get("lat"))
    cur_lon = float(request.form.get("lon"))
    shared_secret = request.form.get("master_secret")

    if not shared_secret:
        return jsonify({"error": "Missing DH shared secret"}), 400

    MASTER_SECRET = shared_secret.encode()

    file = request.files["file"]
    full_data = file.read()

    try:
        meta, encrypted = full_data.split(b"|", 1)
    except:
        return jsonify({"error": "Invalid encrypted file format"}), 400

    saved_lat_str, saved_lon_str, time_str = meta.decode().split(",")

    saved_lat = float(saved_lat_str)
    saved_lon = float(saved_lon_str)
    saved_time = datetime.fromisoformat(time_str)

    # ---------- LOCATION CHECK ----------
    if not close(cur_lat, saved_lat) or not close(cur_lon, saved_lon):
        return jsonify({
            "error": "Location mismatch",
            "current_lat": cur_lat,
            "current_lon": cur_lon,
            "saved_lat": saved_lat,
            "saved_lon": saved_lon
        }), 403

    # ---------- TIME CHECK ----------
    now = datetime.utcnow()
    diff_seconds = abs((now - saved_time).total_seconds())

    if diff_seconds > TIME_WINDOW_MINUTES * 60:
        return jsonify({
            "error": "Time window expired",
            "current_time": now.isoformat(),
            "saved_time": saved_time.isoformat(),
            "difference_seconds": diff_seconds
        }), 403

    # ---------- KEY DERIVATION ----------
    key = derive_key(MASTER_SECRET, saved_lat_str, saved_lon_str, saved_time)

    try:
        decrypted = decrypt_bytes(encrypted, key)
    except:
        return jsonify({
            "error": "Wrong Diffie-Hellman key (shared secret mismatch)"
        }), 403

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=file.filename.replace(".enc", "")
    )

# ================= MAIN =================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

