const SERVER = "http://127.0.0.1:8000";
const username = (localStorage.getItem("username") || "").trim();
if(!username) window.location.href="/";
document.getElementById("me").textContent = username;
document.getElementById("logout").addEventListener("click",()=>{
  localStorage.removeItem("username");
  window.location.href = "/";
})

let selectedUser = "";
const usersEl = document.getElementById("users");
const headerEl = document.getElementById("chatHeader");
const messagesEl = document.getElementById("messages");
const form = document.getElementById("msgForm");
const input = document.getElementById("msgInput");

function abToB64(ab){
  const bytes = new Uint8Array(ab);
  let bin ="";
  for (const b of bytes) bin +=String.fromCharCode(b);
  return btoa(bin);
}
function b64ToAb(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

/* --------------------------
   PEM <-> ArrayBuffer
-------------------------- */
function spkiToPem(spkiAb) {
  const b64 = abToB64(spkiAb);
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----\n`;
}
function pemToSpki(pem) {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return b64ToAb(b64);
}

function openDB(){
  return new Promise((resolve,reject)=>{
    const req = indexedDB.open("e2ee_chat_db",2);
    req.onupgradeneeded = () => {
    const db = req.result;

    if (!db.objectStoreNames.contains("keys")) {
      db.createObjectStore("keys", { keyPath: "username" });
    }
    if (!db.objectStoreNames.contains("trusted")) {
      db.createObjectStore("trusted", { keyPath: "username" });
    }
  };
    req.onsuccess=()=>resolve(req.result);
    req.onerror =() =>reject(req.error);
  })
}
async function trustedGet(user) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("trusted", "readonly");
    const store = tx.objectStore("trusted");
    const req = store.get(user);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function trustedPut(record) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("trusted", "readwrite");
    const store = tx.objectStore("trusted");
    const req = store.put(record);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error);
  });
}
async function idbGet(username) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readonly");
    const store = tx.objectStore("keys");
    const req = store.get(username);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}
async function idbPut(record) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readwrite");
    const store = tx.objectStore("keys");
    const req = store.put(record);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error);
  });
}
async function ensureKeypair() {
  let rec = await idbGet(username);
  if ( rec && rec.privateKey && rec.publicKey){
    return {privateKey:rec.privateKey,publicKey:rec.publicKey}
  }
const keypair = await crypto.subtle.generateKey({
  name: "RSA-OAEP",
  modulusLength:2048,
  publicExponent:new Uint8Array([1,0,1]),
  hash: "SHA-256",
},false,["encrypt","decrypt"]);
await idbPut({username,privateKey:keypair.privateKey,publicKey:keypair.publicKey});
return keypair
}

async function registerMyPublicKey(publickey) {
  const spki = await crypto.subtle.exportKey("spki",publickey);
  const pem = spkiToPem(spki);
  const r = await fetch(`${SERVER}/register_key`,{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({username,public_key_pem:pem}),
  });
  if (!r.ok ) throw new Error("register_key Failed!");
}

async function fetchUserPublicKey(toUser){
  const r = await fetch(`${SERVER}/public_key/${encodeURIComponent(toUser)}`);
  if (!r.ok) throw new Error(`public key not found for ${toUser}`);
  const data = await r.json();
  const spki = pemToSpki(data.public_key_pem);
  const fp = data.fingerprint;

  const saved = await trustedGet(toUser);
  if (!saved) {
    const ok = confirm(
      `${toUser} için ilk kez anahtar görüyorum.\n` +
      `Fingerprint (SHA-256):\n${fp}\n\n` +
      `Bunu kabul ediyor musun?`
    );
    if (!ok) throw new Error("fingerprint not trusted");
    await trustedPut({ username: toUser, fingerprint: fp, saved_at: new Date().toISOString() });
  } else {
    if (saved.fingerprint !== fp) {
      alert(
        `⚠️ DİKKAT: ${toUser} public key değişmiş!\n\n` +
        `Kayıtlı: ${saved.fingerprint}\n` +
        `Sunucu:  ${fp}\n\n` +
        `Bu MITM olabilir. Mesaj gönderme durduruldu.`
      );
      throw new Error("fingerprint mismatch");
    }
  }
  return crypto.subtle.importKey(
    "spki",
    spki,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

const te = new TextEncoder();
const td = new TextDecoder();

async function makePacket(fromUser, toUser, toPublicKey, fromPublicKey, plaintext) {
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, te.encode(plaintext));

  const aesRaw = await crypto.subtle.exportKey("raw", aesKey);

  // alıcı için
  const encKeyTo = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, toPublicKey, aesRaw);
  // gönderici için (kendi mesajını görebilmek için)
  const encKeyFrom = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, fromPublicKey, aesRaw);

  return {
    from: fromUser,
    to: toUser,
    iv_b64: abToB64(iv.buffer),
    ct_b64: abToB64(ct),
    enc_key_to_b64: abToB64(encKeyTo),
    enc_key_from_b64: abToB64(encKeyFrom),
  };
}

async function openPacket(privateKey, packet, myUsername) {
  const encField = packet.from === myUsername ? "enc_key_from_b64" : "enc_key_to_b64";
  const encKeyAb = b64ToAb(packet[encField]);

  const aesRaw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encKeyAb);
  const aesKey = await crypto.subtle.importKey("raw", aesRaw, { name: "AES-GCM" }, false, ["decrypt"]);

  const iv = new Uint8Array(b64ToAb(packet.iv_b64));
  const ct = b64ToAb(packet.ct_b64);

  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
  return td.decode(pt);
}
function renderUsers(list) {
  usersEl.innerHTML = "";
  list
    .filter((u) => u !== username)
    .forEach((u) => {
      const div = document.createElement("div");
      div.className = "user" + (u === selectedUser ? " active" : "");
      div.textContent = u;
      div.onclick = () => {
        selectedUser = u;
        headerEl.textContent = `Şu kişiye yazıyorsun: ${u}`;
        renderUsers(list);
      };
      usersEl.appendChild(div);
    });
}

function appendMessageView({ from, to, msg, created_at }) {
  const div = document.createElement("div");
  div.className = "msg" + (from === username ? " me" : "");

  const meta = document.createElement("div");
  meta.className = "meta";
  const t = created_at ? new Date(created_at).toLocaleString() : "";
  meta.textContent = `${from} → ${to} ${t ? "• " + t : ""}`;

  const body = document.createElement("div");
  body.textContent = msg;

  div.appendChild(meta);
  div.appendChild(body);
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}
let MY_PRIVATE = null;
let MY_PUBLIC = null;

(async () => {
  // 1) keypair hazırla + public key register et
  const { privateKey, publicKey } = await ensureKeypair();
  MY_PRIVATE = privateKey;
  MY_PUBLIC = publicKey;
  await registerMyPublicKey(publicKey);

  // 2) socket bağlan
  const socket = io("http://127.0.0.1:8000", { auth: { username } });

  socket.on("users", (list) => renderUsers(list));

  socket.on("history_packets", async (packets) => {
    messagesEl.innerHTML = "";
    for (const p of packets) {
      // sadece beni ilgilendirenleri göster
      if (p.from !== username && p.to !== username) continue;

      try {
        const text = await openPacket(MY_PRIVATE, p, username);
        appendMessageView({ from: p.from, to: p.to, msg: text, created_at: p.created_at });
      } catch {
        appendMessageView({ from: p.from, to: p.to, msg: "[decrypt failed]", created_at: p.created_at });
      }
    }
  });

  socket.on("new_packet", async (p) => {
    if (p.from !== username && p.to !== username) return;

    try {
      const text = await openPacket(MY_PRIVATE, p, username);
      appendMessageView({ from: p.from, to: p.to, msg: text, created_at: p.created_at });
    } catch {
      appendMessageView({ from: p.from, to: p.to, msg: "[decrypt failed]", created_at: p.created_at });
    }
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = input.value.trim();
    if (!msg) return;

    if (!selectedUser) {
      alert("Önce bir kullanıcı seç.");
      return;
    }

    try {
      const toPub = await fetchUserPublicKey(selectedUser);
      const packet = await makePacket(username, selectedUser, toPub, MY_PUBLIC, msg);
      socket.emit("send_packet", packet);
      input.value = "";
      input.focus();
    } catch (err) {
      alert("Gönderilemedi: " + err.message);
    }
  });
})();









// --- ŞİFRELEMESİZ PROTOTİP---
// const username = (localStorage.getItem("username") || "").trim();
// if (!username) window.location.href = "/";

// document.getElementById("me").textContent = username;

// document.getElementById("logout").addEventListener("click", () => {
//   localStorage.removeItem("username");
//   window.location.href = "/";
// });

// let selectedUser = "";
// const usersEl = document.getElementById("users");
// const headerEl = document.getElementById("chatHeader");
// const messagesEl = document.getElementById("messages");
// const form = document.getElementById("msgForm");
// const input = document.getElementById("msgInput");

// const socket = io({ auth: { username } });

// function renderUsers(list) {
//   usersEl.innerHTML = "";
//   list
//     .filter(u => u !== username)
//     .forEach(u => {
//       const div = document.createElement("div");
//       div.className = "user" + (u === selectedUser ? " active" : "");
//       div.textContent = u;
//       div.onclick = () => {
//         selectedUser = u;
//         headerEl.textContent = `Şu kişiye yazıyorsun: ${u}`;
//         renderUsers(list);
//       };
//       usersEl.appendChild(div);
//     });
// }

// function appendMessage(m) {
//   const div = document.createElement("div");
//   div.className = "msg" + (m.from === username ? " me" : "");

//   const meta = document.createElement("div");
//   meta.className = "meta";
//   const t = m.created_at ? new Date(m.created_at).toLocaleString() : "";
//   meta.textContent = `${m.from} → ${m.to} ${t ? "• " + t : ""}`;

//   const body = document.createElement("div");
//   body.textContent = m.msg;

//   div.appendChild(meta);
//   div.appendChild(body);
//   messagesEl.appendChild(div);
//   messagesEl.scrollTop = messagesEl.scrollHeight;
// }

// socket.on("users", (list) => {
//   renderUsers(list);
// });

// socket.on("history", (rows) => {
//   messagesEl.innerHTML = "";
//   rows.forEach(appendMessage);
// });

// socket.on("new_message", (m) => {
//   // sadece benimle ilgili mesajları göster
//   if (m.from === username || m.to === username) appendMessage(m);
// });

// form.addEventListener("submit", (e) => {
//   e.preventDefault();
//   const msg = input.value.trim();
//   if (!msg) return;

//   if (!selectedUser) {
//     alert("Önce bir kullanıcı seç.");
//     return;
//   }

//   socket.emit("send_message", { to: selectedUser, msg });
//   input.value = "";
//   input.focus();
// });
