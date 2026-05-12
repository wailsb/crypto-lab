/* global crypto */

const wsUrl = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`;
let socket = null;
let deviceId =
  localStorage.getItem("deviceId") ||
  (crypto?.randomUUID ? crypto.randomUUID() : `device-${Math.random().toString(16).slice(2)}`);
let deviceName = "";
let devices = [];

const sessionState = {
  active: false,
  sessionId: null,
  peerId: null,
  transport: "ecdh-aes-gcm-ecdsa",
  payloadAlgo: "none",
  sharedKey: null,
  ecdhKeyPair: null,
  ecdsaKeyPair: null,
  peerSignKey: null,
};

const ui = {
  deviceName: document.getElementById("deviceName"),
  connectBtn: document.getElementById("connectBtn"),
  deviceInfo: document.getElementById("deviceInfo"),
  deviceList: document.getElementById("deviceList"),
  targetDevice: document.getElementById("targetDevice"),
  payloadAlgo: document.getElementById("payloadAlgo"),
  startSessionBtn: document.getElementById("startSessionBtn"),
  sessionStatus: document.getElementById("sessionStatus"),
  payloadKeyConfig: document.getElementById("payloadKeyConfig"),
  chat: document.getElementById("chat"),
  messageInput: document.getElementById("messageInput"),
  sendBtn: document.getElementById("sendBtn"),
};

ui.connectBtn.addEventListener("click", connect);
ui.startSessionBtn.addEventListener("click", startSession);
ui.sendBtn.addEventListener("click", sendMessage);
ui.payloadAlgo.addEventListener("change", renderPayloadConfig);

renderPayloadConfig();
ensureSecureContext();
autoConnect();
updateSessionStatus("idle");

function ensureSecureContext() {
  if (!window.isSecureContext || !crypto?.subtle) {
    ui.deviceInfo.textContent =
      "Status: insecure context. Devices can register, but secure sessions require https:// or localhost.";
    ui.deviceInfo.classList.add("error");
  }
}

function autoConnect() {
  if (ui.deviceName.value.trim() === "") {
    ui.deviceName.value = `Device-${deviceId.slice(0, 6)}`;
  }
  setTimeout(() => {
    if (!socket) {
      connect();
    }
  }, 500);
}

async function connect() {
  if (socket) {
    return;
  }
  deviceName = ui.deviceName.value.trim() || "Device";
  localStorage.setItem("deviceId", deviceId);

  socket = new WebSocket(wsUrl);
  socket.onopen = async () => {
    ui.deviceInfo.textContent = `Status: connected as ${deviceName}`;
    ui.deviceInfo.classList.remove("error");
    socket.send(
      JSON.stringify({
        type: "register",
        deviceId,
        name: deviceName,
      })
    );
    socket.send(JSON.stringify({ type: "list_devices" }));
  };

  socket.onmessage = async (event) => {
    const data = JSON.parse(event.data);
    await handleServerMessage(data);
  };

  socket.onclose = () => {
    socket = null;
    ui.deviceInfo.textContent = "Status: disconnected";
    ui.deviceInfo.classList.add("error");
  };
}

async function handleServerMessage(data) {
  switch (data.type) {
    case "registered":
      ui.deviceInfo.textContent = `Registered as ${data.name} (${data.deviceId})`;
      ui.deviceInfo.classList.remove("error");
      break;
    case "device_list":
      devices = data.devices.filter((d) => d.deviceId !== deviceId);
      renderDeviceList();
      break;
    case "session_offer":
      await acceptSessionOffer(data);
      break;
    case "session_answer":
      await finalizeSession(data);
      break;
    case "relay":
      await receiveMessage(data);
      break;
    case "session_ended":
      resetSession("Session ended");
      break;
    case "error":
      logMessage("System", data.message, true);
      break;
    default:
      break;
  }
}

function renderDeviceList() {
  ui.deviceList.innerHTML = "";
  ui.targetDevice.innerHTML = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select a device to chat with";
  placeholder.disabled = true;
  placeholder.selected = true;
  ui.targetDevice.appendChild(placeholder);

  if (devices.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No devices connected yet.";
    ui.deviceList.appendChild(li);
    ui.startSessionBtn.disabled = true;
    return;
  }

  devices.forEach((device) => {
    const li = document.createElement("li");
    li.textContent = `${device.name} (${device.status})`;
    ui.deviceList.appendChild(li);

    if (device.status === "available") {
      const option = document.createElement("option");
      option.value = device.deviceId;
      option.textContent = `${device.name} (${device.deviceId.slice(0, 8)})`;
      ui.targetDevice.appendChild(option);
    }
  });

  ui.startSessionBtn.disabled = ui.targetDevice.options.length <= 1;
}

function renderPayloadConfig() {
  const algo = ui.payloadAlgo.value;
  if (algo === "caesar") {
    ui.payloadKeyConfig.textContent = "Caesar key: use a shift (0-25) in message like 'SHIFT:3|your message'.";
  } else if (algo === "vigenere") {
    ui.payloadKeyConfig.textContent = "Vigenere key: prefix message with 'KEY:yourkey|'";
  } else if (algo === "hill") {
    ui.payloadKeyConfig.textContent = "Hill key: prefix message with 'MATRIX:3,3,2,5|' (2x2).";
  } else if (algo === "otp") {
    ui.payloadKeyConfig.textContent = "OTP: prefix message with 'OTP:hexkey|' (length = message bytes).";
  } else {
    ui.payloadKeyConfig.textContent = "No payload cipher.";
  }
}

async function startSession() {
  const target = ui.targetDevice.value;
  if (!target || !socket) {
    return;
  }
  if (!window.isSecureContext || !crypto?.subtle) {
    logMessage("System", "Secure sessions require https:// or localhost.", true);
    return;
  }
  sessionState.payloadAlgo = ui.payloadAlgo.value;
  sessionState.ecdhKeyPair = await generateEcdhKeyPair();
  sessionState.ecdsaKeyPair = sessionState.ecdsaKeyPair || (await generateEcdsaKeyPair());
  sessionState.active = false;
  updateSessionStatus("pending");

  const ecdhPublicKey = await exportPublicKey(sessionState.ecdhKeyPair.publicKey);
  const signPublicKey = await exportPublicKey(sessionState.ecdsaKeyPair.publicKey);
  const offerBody = { ecdhPublicKey, signPublicKey, timestamp: Date.now() };
  const signature = await signPayload(offerBody, sessionState.ecdsaKeyPair.privateKey);

  socket.send(
    JSON.stringify({
      type: "start_session",
      to: target,
      protocol: sessionState.transport,
      offer: { ...offerBody, signature },
    })
  );

  sessionState.peerId = target;
  setTimeout(() => {
    if (!sessionState.active && sessionState.peerId === target) {
      socket.send(JSON.stringify({ type: "end_session", sessionId: sessionState.sessionId }));
      resetSession("Session request timed out. Try again.");
    }
  }, 10000);
}

async function acceptSessionOffer(data) {
  if (!window.isSecureContext || !crypto?.subtle) {
    logMessage("System", "Cannot accept session: secure context required.", true);
    return;
  }
  try {
    const offer = data.offer;
    const peerSignKey = await importPublicKey(offer.signPublicKey, "ECDSA");

    const valid = await verifySignature(
      { ecdhPublicKey: offer.ecdhPublicKey, signPublicKey: offer.signPublicKey, timestamp: offer.timestamp },
      offer.signature,
      peerSignKey
    );

    if (!valid) {
      logMessage("System", "Invalid signature in offer", true);
      return;
    }

    sessionState.ecdhKeyPair = await generateEcdhKeyPair();
    sessionState.ecdsaKeyPair = sessionState.ecdsaKeyPair || (await generateEcdsaKeyPair());
    sessionState.peerSignKey = peerSignKey;

    const peerEcdhKey = await importPublicKey(offer.ecdhPublicKey, "ECDH");
    sessionState.sharedKey = await deriveSharedKey(sessionState.ecdhKeyPair.privateKey, peerEcdhKey);

    const ecdhPublicKey = await exportPublicKey(sessionState.ecdhKeyPair.publicKey);
    const signPublicKey = await exportPublicKey(sessionState.ecdsaKeyPair.publicKey);
    const answerBody = { ecdhPublicKey, signPublicKey, timestamp: Date.now() };
    const signature = await signPayload(answerBody, sessionState.ecdsaKeyPair.privateKey);

    socket.send(
      JSON.stringify({
        type: "session_answer",
        to: data.from,
        sessionId: data.sessionId,
        answer: { ...answerBody, signature },
      })
    );

    sessionState.active = true;
    sessionState.sessionId = data.sessionId;
    sessionState.peerId = data.from;
    updateSessionStatus("active", data.from);
    logMessage("System", `Secure session established with ${data.from}`);
  } catch (err) {
    logMessage("System", "Failed to accept session offer", true);
  }
}

async function finalizeSession(data) {
  const answer = data.answer;
  const peerSignKey = await importPublicKey(answer.signPublicKey, "ECDSA");

  const valid = await verifySignature(
    { ecdhPublicKey: answer.ecdhPublicKey, signPublicKey: answer.signPublicKey, timestamp: answer.timestamp },
    answer.signature,
    peerSignKey
  );

  if (!valid) {
    logMessage("System", "Invalid signature in answer", true);
    return;
  }

  sessionState.peerSignKey = peerSignKey;
  const peerEcdhKey = await importPublicKey(answer.ecdhPublicKey, "ECDH");
  sessionState.sharedKey = await deriveSharedKey(sessionState.ecdhKeyPair.privateKey, peerEcdhKey);
  sessionState.active = true;
  sessionState.sessionId = data.sessionId;
  updateSessionStatus("active", data.from);
  logMessage("System", `Secure session established with ${data.from}`);
}

async function sendMessage() {
  if (!sessionState.active || !socket) {
    logMessage("System", "No active session", true);
    return;
  }
  const raw = ui.messageInput.value.trim();
  if (!raw) {
    return;
  }

  const payloadText = applyPayloadCipher(raw, sessionState.payloadAlgo);
  const encrypted = await encryptMessage(payloadText, sessionState.sharedKey);

  socket.send(
    JSON.stringify({
      type: "relay",
      to: sessionState.peerId,
      payload: {
        protocol: sessionState.transport,
        payloadAlgo: sessionState.payloadAlgo,
        data: encrypted,
      },
    })
  );

  logMessage("Me", raw);
  ui.messageInput.value = "";
}

async function receiveMessage(data) {
  if (!sessionState.active) {
    return;
  }
  const payload = data.payload;
  const decrypted = await decryptMessage(payload.data, sessionState.sharedKey);
  const finalText = removePayloadCipher(decrypted, payload.payloadAlgo);
  logMessage(`Peer`, finalText);
}

function resetSession(reason) {
  sessionState.active = false;
  sessionState.sessionId = null;
  sessionState.peerId = null;
  sessionState.sharedKey = null;
  updateSessionStatus("idle");
  logMessage("System", reason || "Session ended", true);
}

function updateSessionStatus(state, peer = "") {
  if (!ui.sessionStatus) {
    return;
  }
  if (state === "active") {
    ui.sessionStatus.textContent = `Session status: active with ${peer}`;
    ui.sendBtn.disabled = false;
  } else if (state === "pending") {
    ui.sessionStatus.textContent = "Session status: establishing...";
    ui.sendBtn.disabled = true;
  } else {
    ui.sessionStatus.textContent = "Session status: idle";
    ui.sendBtn.disabled = true;
  }
}

function logMessage(sender, text, isError = false) {
  const container = document.createElement("div");
  container.className = "message";
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = `${sender} • ${new Date().toLocaleTimeString()}`;
  const body = document.createElement("div");
  body.className = "text";
  body.textContent = text;
  if (isError) {
    body.classList.add("error");
  }
  container.appendChild(meta);
  container.appendChild(body);
  ui.chat.appendChild(container);
  ui.chat.scrollTop = ui.chat.scrollHeight;
}

async function generateEcdhKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveKey"]
  );
}

async function generateEcdsaKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );
}

async function deriveSharedKey(privateKey, peerPublicKey) {
  return crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: peerPublicKey,
    },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function signPayload(payload, privateKey) {
  const encoded = new TextEncoder().encode(JSON.stringify(payload));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    encoded
  );
  return bufferToBase64(signature);
}

async function verifySignature(payload, signature, publicKey) {
  const encoded = new TextEncoder().encode(JSON.stringify(payload));
  const sig = base64ToBuffer(signature);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    sig,
    encoded
  );
}

async function encryptMessage(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  return {
    iv: bufferToBase64(iv),
    ciphertext: bufferToBase64(ciphertext),
  };
}

async function decryptMessage(payload, key) {
  const iv = base64ToBuffer(payload.iv);
  const ciphertext = base64ToBuffer(payload.ciphertext);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

async function exportPublicKey(key) {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return jwk;
}

async function importPublicKey(jwk, algo) {
  if (algo === "ECDH") {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
  }
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

function applyPayloadCipher(text, algo) {
  if (algo === "caesar") {
    return caesarEncryptFromPrefix(text);
  }
  if (algo === "vigenere") {
    return vigenereEncryptFromPrefix(text);
  }
  if (algo === "hill") {
    return hillEncryptFromPrefix(text);
  }
  if (algo === "otp") {
    return otpEncryptFromPrefix(text);
  }
  return text;
}

function removePayloadCipher(text, algo) {
  if (algo === "caesar") {
    return caesarDecryptFromPrefix(text);
  }
  if (algo === "vigenere") {
    return vigenereDecryptFromPrefix(text);
  }
  if (algo === "hill") {
    return hillDecryptFromPrefix(text);
  }
  if (algo === "otp") {
    return otpDecryptFromPrefix(text);
  }
  return text;
}

function caesarEncryptFromPrefix(text) {
  if (!text.startsWith("SHIFT:")) {
    return text;
  }
  const [prefix, ...rest] = text.split("|");
  const shift = parseInt(prefix.replace("SHIFT:", ""), 10) || 0;
  const encrypted = caesarEncrypt(rest.join("|"), shift);
  return `SHIFT:${shift}|${encrypted}`;
}

function caesarDecryptFromPrefix(text) {
  if (!text.startsWith("SHIFT:")) {
    return text;
  }
  const [prefix, ...rest] = text.split("|");
  const shift = parseInt(prefix.replace("SHIFT:", ""), 10) || 0;
  return caesarEncrypt(rest.join("|"), (26 - shift) % 26);
}

function caesarEncrypt(text, shift) {
  return text.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function vigenereEncryptFromPrefix(text) {
  if (!text.startsWith("KEY:")) {
    return text;
  }
  const [prefix, ...rest] = text.split("|");
  const key = prefix.replace("KEY:", "").toLowerCase();
  const encrypted = vigenereEncrypt(rest.join("|"), key);
  return `KEY:${key}|${encrypted}`;
}

function vigenereDecryptFromPrefix(text) {
  if (!text.startsWith("KEY:")) {
    return text;
  }
  const [prefix, ...rest] = text.split("|");
  const key = prefix.replace("KEY:", "").toLowerCase();
  return vigenereDecrypt(rest.join("|"), key);
}

function vigenereEncrypt(text, key) {
  let result = "";
  let idx = 0;
  for (const c of text) {
    const lower = c.toLowerCase();
    if (lower < "a" || lower > "z") {
      result += c;
      continue;
    }
    const k = key[idx % key.length].charCodeAt(0) - 97;
    const base = c <= "Z" ? 65 : 97;
    const enc = ((c.charCodeAt(0) - base + k) % 26) + base;
    result += String.fromCharCode(enc);
    idx++;
  }
  return result;
}

function vigenereDecrypt(text, key) {
  let result = "";
  let idx = 0;
  for (const c of text) {
    const lower = c.toLowerCase();
    if (lower < "a" || lower > "z") {
      result += c;
      continue;
    }
    const k = key[idx % key.length].charCodeAt(0) - 97;
    const base = c <= "Z" ? 65 : 97;
    const dec = ((c.charCodeAt(0) - base - k + 26) % 26) + base;
    result += String.fromCharCode(dec);
    idx++;
  }
  return result;
}

function hillEncryptFromPrefix(text) {
  if (!text.startsWith("MATRIX:")) {
    return text;
  }
  const [prefix, ...rest] = text.split("|");
  const keyVals = prefix.replace("MATRIX:", "").split(",").map(Number);
  if (keyVals.length !== 4) {
    return text;
  }
  const encrypted = hillEncrypt(rest.join("|"), keyVals);
  return `MATRIX:${keyVals.join(",")}|${encrypted}`;
}

function hillDecryptFromPrefix(text) {
  if (!text.startsWith("MATRIX:")) {
    return text;
  }
  const [prefix, ...rest] = text.split("|");
  const keyVals = prefix.replace("MATRIX:", "").split(",").map(Number);
  if (keyVals.length !== 4) {
    return text;
  }
  return hillDecrypt(rest.join("|"), keyVals);
}

function hillEncrypt(text, keyVals) {
  const mod = 26;
  const [a, b, c, d] = keyVals;
  const clean = text.toLowerCase().replace(/[^a-z]/g, "");
  const padded = clean.length % 2 === 0 ? clean : clean + "x";
  let result = "";
  for (let i = 0; i < padded.length; i += 2) {
    const x = padded.charCodeAt(i) - 97;
    const y = padded.charCodeAt(i + 1) - 97;
    const e1 = (a * x + b * y) % mod;
    const e2 = (c * x + d * y) % mod;
    result += String.fromCharCode(e1 + 97, e2 + 97);
  }
  return result;
}

function otpEncryptFromPrefix(text) {
  if (!text.startsWith("OTP:")) {
    return text;
  }
  const [prefix, ...rest] = text.split("|");
  const keyHex = prefix.replace("OTP:", "");
  const message = rest.join("|");
  const keyBytes = hexToBytes(keyHex);
  const msgBytes = new TextEncoder().encode(message);
  if (keyBytes.length < msgBytes.length) {
    return text;
  }
  const out = msgBytes.map((b, i) => b ^ keyBytes[i]);
  return `OTP:${keyHex}|${bytesToHex(out)}`;
}

function otpDecryptFromPrefix(text) {
  if (!text.startsWith("OTP:")) {
    return text;
  }
  const [prefix, ...rest] = text.split("|");
  const keyHex = prefix.replace("OTP:", "");
  const cipherHex = rest.join("|");
  const keyBytes = hexToBytes(keyHex);
  const cipherBytes = hexToBytes(cipherHex);
  const out = cipherBytes.map((b, i) => b ^ keyBytes[i]);
  return new TextDecoder().decode(out);
}

function hillDecrypt(text, keyVals) {
  const mod = 26;
  const [a, b, c, d] = keyVals;
  const det = (a * d - b * c) % mod;
  const detInv = modInverse(det, mod);
  if (detInv === null) {
    return text;
  }
  const inv = [
    (d * detInv) % mod,
    ((-b + mod) * detInv) % mod,
    ((-c + mod) * detInv) % mod,
    (a * detInv) % mod,
  ];
  const clean = text.toLowerCase().replace(/[^a-z]/g, "");
  const padded = clean.length % 2 === 0 ? clean : clean + "x";
  let result = "";
  for (let i = 0; i < padded.length; i += 2) {
    const x = padded.charCodeAt(i) - 97;
    const y = padded.charCodeAt(i + 1) - 97;
    const p1 = (inv[0] * x + inv[1] * y) % mod;
    const p2 = (inv[2] * x + inv[3] * y) % mod;
    result += String.fromCharCode(p1 + 97, p2 + 97);
  }
  return result;
}

function modInverse(a, mod) {
  a = ((a % mod) + mod) % mod;
  for (let x = 1; x < mod; x++) {
    if ((a * x) % mod === 1) {
      return x;
    }
  }
  return null;
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
