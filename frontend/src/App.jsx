import { useState } from "react";

const API = "https://geo-crypto-project.onrender.com";

export default function App() {
  const [encFile, setEncFile] = useState(null);
  const [decFile, setDecFile] = useState(null);

  const [privateKey, setPrivateKey] = useState(null);
  const [publicKeyBase64, setPublicKeyBase64] = useState("");
  const [peerPublicKeyBase64, setPeerPublicKeyBase64] = useState("");
  const [sharedSecretBase64, setSharedSecretBase64] = useState("");

  const [email, setEmail] = useState("");
  const [timeLimit, setTimeLimit] = useState(5);
  const [radius, setRadius] = useState(1);
  const [overrideSecret, setOverrideSecret] = useState("");

  // ================= LOCATION =================
  const getLocation = () =>
    new Promise((resolve, reject) => {
      navigator.geolocation.getCurrentPosition(
        (pos) =>
          resolve({
            lat: pos.coords.latitude.toFixed(6),
            lon: pos.coords.longitude.toFixed(6),
          }),
        () => reject("Location denied")
      );
    });

  // ================= HELPERS =================
  const abToBase64 = (ab) => {
    const bytes = new Uint8Array(ab);
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  };

  const base64ToAb = (b64) => {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  };

  // ================= KEY GENERATION =================
  const generateKeys = async () => {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );

      setPrivateKey(keyPair.privateKey);

      const spki = await window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
      );

      setPublicKeyBase64(abToBase64(spki));
      alert("Keys generated successfully.");
    } catch {
      alert("Key generation failed.");
    }
  };

  // ================= SEND PUBLIC KEY =================
  const handleSendKey = async () => {
    if (!email) return alert("Enter recipient email.");
    if (!publicKeyBase64) return alert("Generate keys first.");

    const formData = new FormData();
    formData.append("email", email);
    formData.append("public_key", publicKeyBase64);

    const res = await fetch(`${API}/send-key`, {
      method: "POST",
      body: formData,
    });

    const data = await res.json();
    alert(data.message || data.error);
  };

  // ================= DERIVE SHARED SECRET =================
  const deriveSharedSecret = async () => {
    if (!privateKey) return alert("Generate your keys first.");
    if (!peerPublicKeyBase64)
      return alert("Paste receiver public key.");

    try {
      const peerPubKey = await window.crypto.subtle.importKey(
        "spki",
        base64ToAb(peerPublicKeyBase64),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );

      const bits = await window.crypto.subtle.deriveBits(
        { name: "ECDH", public: peerPubKey },
        privateKey,
        256
      );

      setSharedSecretBase64(abToBase64(bits));
      alert("Shared secret derived successfully.");
    } catch {
      alert("Failed to derive shared secret.");
    }
  };

  // ================= ENCRYPT =================
  const handleEncrypt = async () => {
    if (!encFile) return alert("Select file to encrypt.");
    if (!sharedSecretBase64)
      return alert("Derive shared secret first.");
    if (!email) return alert("Enter recipient email.");

    try {
      const loc = await getLocation();

      const formData = new FormData();
      formData.append("file", encFile);
      formData.append("lat", loc.lat);
      formData.append("lon", loc.lon);
      formData.append("master_secret", sharedSecretBase64);
      formData.append("time_limit", timeLimit);
      formData.append("radius", radius);
      formData.append("email", email);

      const res = await fetch(`${API}/encrypt`, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json();
        alert(err.error);
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = encFile.name + ".enc";
      a.click();

      alert("File encrypted successfully. Override secret sent via email.");
    } catch {
      alert("Encryption failed.");
    }
  };

  // ================= DECRYPT =================
  const handleDecrypt = async () => {
    if (!decFile) return alert("Select encrypted file.");
    if (!sharedSecretBase64)
      return alert("Derive shared secret first.");

    try {
      const loc = await getLocation();

      const formData = new FormData();
      formData.append("file", decFile);
      formData.append("lat", loc.lat);
      formData.append("lon", loc.lon);
      formData.append("master_secret", sharedSecretBase64);
      formData.append("override_secret", overrideSecret);

      const res = await fetch(`${API}/decrypt`, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json();
        alert(err.error);
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = decFile.name.replace(".enc", "");
      a.click();

      alert("File decrypted successfully.");
    } catch {
      alert("Decryption failed.");
    }
  };

  // ================= UI =================
  return (
    <div style={{ padding: 30 }}>
      <h1>SecureGeoCrypt</h1>

      <h2>🔑 Key Exchange</h2>

      <input
        type="email"
        placeholder="Recipient Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <br /><br />

      <button onClick={generateKeys}>Generate My Keys</button>
      <button onClick={handleSendKey}>Send Public Key via Email</button>

      <p>Your Public Key:</p>
      <textarea
        value={publicKeyBase64}
        readOnly
        rows={3}
        style={{ width: "100%" }}
      />

      <p>Paste Receiver Public Key:</p>
      <textarea
        value={peerPublicKeyBase64}
        onChange={(e) => setPeerPublicKeyBase64(e.target.value)}
        rows={3}
        style={{ width: "100%" }}
      />

      <button onClick={deriveSharedSecret}>
        Derive Shared Secret
      </button>

      <hr />

      <h2>🔐 Encryption Settings</h2>

      <input
        type="number"
        placeholder="Time Limit (minutes)"
        value={timeLimit}
        onChange={(e) => setTimeLimit(e.target.value)}
      />
      <br /><br />

      <input
        type="number"
        placeholder="Radius (km)"
        value={radius}
        onChange={(e) => setRadius(e.target.value)}
      />

      <hr />

      <h2>📦 Encrypt</h2>
      <input
        type="file"
        onChange={(e) => setEncFile(e.target.files[0])}
      />
      <button onClick={handleEncrypt}>Encrypt File</button>

      <hr />

      <h2>🔓 Decrypt</h2>
      <input
        type="file"
        onChange={(e) => setDecFile(e.target.files[0])}
      />
      <br /><br />

      <input
        type="text"
        placeholder="Override Secret (if time expired)"
        value={overrideSecret}
        onChange={(e) => setOverrideSecret(e.target.value)}
      />
      <br /><br />

      <button onClick={handleDecrypt}>Decrypt File</button>
    </div>
  );
}