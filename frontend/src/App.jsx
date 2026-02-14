import { useState } from "react";

export default function App() {
  const [encFile, setEncFile] = useState(null);
  const [decFile, setDecFile] = useState(null);

  const [privateKey, setPrivateKey] = useState(null);      // CryptoKey
  const [publicKeyBase64, setPublicKeyBase64] = useState(""); // exportable public key
  const [peerPublicKeyBase64, setPeerPublicKeyBase64] = useState(""); // pasted key
  const [sharedSecretBase64, setSharedSecretBase64] = useState("");   // derived secret

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

  // ===== Helpers for base64 <-> ArrayBuffer =====
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

  // ===== 1) Generate ECDH keys in browser =====
  const generateKeys = async () => {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true, // extractable
        ["deriveBits"]
      );

      setPrivateKey(keyPair.privateKey);

      // Export public key (SPKI) so user can share it
      const spki = await window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
      );
      setPublicKeyBase64(abToBase64(spki));

      alert("ECDH keys generated. Share your Public Key with the receiver.");
    } catch (e) {
      console.error(e);
      alert("Key generation failed");
    }
  };

  // ===== 2) Derive shared secret using my private + peer public =====
  const deriveSharedSecret = async () => {
    if (!privateKey) {
      alert("Generate your keys first");
      return;
    }
    if (!peerPublicKeyBase64) {
      alert("Paste the receiver's public key");
      return;
    }

    try {
      // Import peer public key (SPKI)
      const peerPubKey = await window.crypto.subtle.importKey(
        "spki",
        base64ToAb(peerPublicKeyBase64),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );

      // Derive 256-bit shared secret
      const bits = await window.crypto.subtle.deriveBits(
        {
          name: "ECDH",
          public: peerPubKey,
        },
        privateKey,
        256
      );

      // Convert to base64 to send to backend
      setSharedSecretBase64(abToBase64(bits));
      alert("Shared secret derived!");
    } catch (e) {
      console.error(e);
      alert("Failed to derive shared secret");
    }
  };

  // ===== ENCRYPT =====
  const handleEncrypt = async () => {
    if (!encFile) return alert("Select a file");
    if (!sharedSecretBase64) return alert("Derive shared secret first!");

    try {
      const loc = await getLocation();

      const formData = new FormData();
      formData.append("file", encFile);
      formData.append("lat", loc.lat);
      formData.append("lon", loc.lon);
      formData.append("master_secret", sharedSecretBase64);

      const res = await fetch("https://geo-crypto-project.onrender.com/encrypt", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        alert("Encryption failed");
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = encFile.name + ".enc";
      a.click();
    } catch {
      alert("Encryption failed or location denied");
    }
  };

  // ===== DECRYPT =====
  const handleDecrypt = async () => {
    if (!decFile) return alert("Select encrypted file");
    if (!sharedSecretBase64) return alert("Derive shared secret first!");

    try {
      const loc = await getLocation();

      const formData = new FormData();
      formData.append("file", decFile);
      formData.append("lat", loc.lat);
      formData.append("lon", loc.lon);
      formData.append("master_secret", sharedSecretBase64);

      const res = await fetch("https://geo-crypto-project.onrender.com/decrypt", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        alert("Access denied (wrong key/location/time)");
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = decFile.name.replace(".enc", "");
      a.click();
    } catch {
      alert("Decryption failed");
    }
  };

  return (
    <div style={{ padding: 30 }}>
      <h1>Geo-Fenced Crypto + REAL ECDH</h1>

      <h2>🔑 Diffie-Hellman (ECDH) Key Exchange</h2>

      <button onClick={generateKeys}>Generate My Keys</button>

      <p><b>Your Public Key (share this):</b></p>
      <textarea value={publicKeyBase64} readOnly rows={4} style={{ width: "100%" }} />

      <p><b>Paste Receiver Public Key:</b></p>
      <textarea
        value={peerPublicKeyBase64}
        onChange={(e) => setPeerPublicKeyBase64(e.target.value)}
        rows={4}
        style={{ width: "100%" }}
      />

      <button onClick={deriveSharedSecret}>Derive Shared Secret</button>

      <hr />

      <h2>Encrypt</h2>
      <input type="file" onChange={(e) => setEncFile(e.target.files[0])} />
      <button onClick={handleEncrypt}>Encrypt File</button>

      <h2>Decrypt</h2>
      <input type="file" onChange={(e) => setDecFile(e.target.files[0])} />
      <button onClick={handleDecrypt}>Decrypt File</button>
    </div>
  );
}
