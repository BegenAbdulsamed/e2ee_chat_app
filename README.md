

````md
# E2EE Chat (FastAPI + Socket.IO + WebCrypto)

Bu projede **FastAPI + Socket.IO** ile çalışan, tarayıcı tarafında **WebCrypto** kullanarak **uçtan uca şifreli (E2EE)** mesajlaşma yapan basit bir chat uygulaması geliştirdik.

## Projede Ne Yaptık? (Genel Mantık)

- Mesaj **tarayıcıda şifrelenir**.
- Sunucu mesajın **düz halini asla görmez**.
- Sunucu yalnızca **şifreli paketi** alır, **DB’ye kaydeder** ve **diğer kullanıcıya iletir**.
- Şifreleme:
  - Mesaj: **AES-GCM**
  - AES anahtarı paylaşımı: **RSA-OAEP** (alıcının public key’i ile)

---

## 1) Backend — `server_app.py`

### 1.1 Kullanılan Kütüphaneler
- `socketio.AsyncServer`: gerçek zamanlı iletişim (Socket.IO)
- `FastAPI`: HTTP endpointleri ve sayfa servis etmek
- `SQLAlchemy`: SQLite DB’ye kayıt
- `Jinja2Templates`: `index.html` ve `chat.html` render etmek
- `pydantic.BaseModel`: `/register_key` endpoint’ine gelen JSON’u doğrulamak
- `datetime`: mesaj zamanı kaydetmek

---

### 1.2 Veritabanı (SQLite) ve Tablolar

SQLite bağlantısı:
```py
engine = create_engine("sqlite:///./chat.db")
SessionLocal = sessionmaker(bind=engine)
````

#### `Message` tablosu (`messages`)

Sunucunun sakladığı şey **mesajın şifreli paketi**dir:

* `from_user`, `to_user`: kimden kime
* `iv_b64`: AES-GCM nonce/iv (base64)
* `ct_b64`: AES-GCM ciphertext (base64)
* `enc_key_to_b64`: AES anahtarının **alıcı public key’i ile şifrelenmiş** hali
* `enc_key_from_b64`: AES anahtarının **gönderici public key’i ile şifrelenmiş** hali (gönderici kendi mesajını da açabilsin diye)
* `created_at`: timestamp

#### `PublicKey` tablosu (`public_keys`)

Kullanıcıların public key’i burada saklanır:

* `username`: kullanıcı adı (unique)
* `public_key_pem`: public key PEM formatında metin
* `fingerprint`: (eklendiyse) key doğrulama için özet değer

Tablolar:

```py
Base.metadata.create_all(bind=engine)
```

---

### 1.3 Uygulama Kurulumu

* `sio = socketio.AsyncServer(...)` → Socket.IO sunucusu
* `api = FastAPI()` → HTTP API
* `api.mount("/static", ...)` → statik dosyaları servis eder (`static/app.js`, css vb.)
* `templates = Jinja2Templates(...)` → HTML template klasörü
* `ONLINE = {}` → online kullanıcı listesi:

  * `ONLINE[username] = sid`

---

### 1.4 HTTP Endpointleri

#### `POST /register_key`

Amaç: client’ın public key’ini server’a kaydetmek.

Adımlar:

* `username` ve `public_key_pem` alınır
* `username` boşsa hata
* `public_key_pem` içinde `"BEGIN PUBLIC KEY"` yoksa hata (PEM kontrolü)
* DB’de aynı `username` varsa günceller, yoksa yeni kayıt oluşturur
* `{ "ok": true }` döner

#### `GET /public_key/{username}`

Amaç: diğer client’ların bu kullanıcının public key’ini alabilmesi.

Adımlar:

* DB’den `username` ile public key çekilir
* yoksa `404`
* `{ username, public_key_pem }` döner

---

### 1.5 Sayfa Endpointleri

* `GET /` → `index.html` (kullanıcı adı girme ekranı)
* `GET /chat` → `chat.html` (mesajlaşma ekranı)

---

### 1.6 Socket.IO Eventleri

#### `connect(sid, environ, auth)`

Tarayıcı Socket.IO ile bağlanınca çalışır.

Adımlar:

* `auth` içinden `username` alınır (`io({ auth: { username } })`)
* `username` yoksa bağlantı reddedilir (`return False`)
* aynı `username` online ise reddedilir
* `ONLINE[username] = sid`
* `sio.save_session(sid, {"username": username})`
* tüm client’lara `users` event’i ile online kullanıcı listesi gönderilir
* DB’den son 50 mesaj çekilir, paket formatına çevrilir ve sadece bu kullanıcıya `history_packets` olarak gönderilir

#### `disconnect(sid)`

Bağlantı kopunca çalışır.

Adımlar:

* session’dan `username` alınır
* `ONLINE` içinde eşleşme varsa silinir
* güncel liste tüm client’lara `users` event’i ile gönderilir

#### `send_message(sid, packet)`

Client “şifreli mesaj paketi” gönderince çalışır.

Adımlar:

* session’dan gerçek gönderen `username` alınır (`sender`)
* pakette zorunlu alanlar kontrol edilir:

  * `from`, `to`, `iv_b64`, `ct_b64`, `enc_key_to_b64`, `enc_key_from_b64`
* `packet["from"]` gerçekten `sender` mı kontrol edilir (spoof engeli)
* paket DB’ye **şifreli haliyle** kaydedilir
* `created_at` eklenir
* alıcı online ise alıcıya `new_packet` emit edilir
* göndericiye de `new_packet` emit edilir (gönderici kendi mesajını da görsün diye)

---

### 1.7 FastAPI + Socket.IO Birleşimi

```py
app = socketio.ASGIApp(sio, other_asgi_app=api)
```

Bu satır:

* `/register_key`, `/public_key`, `/chat` gibi HTTP isteklerini **FastAPI’ye**
* `/socket.io/...` bağlantılarını **Socket.IO’ya** yönlendirir

---

## 2) Frontend — `static/app.js`

Bu dosya tarayıcıda şunları yapar:

* kullanıcı adını yönetir
* RSA keypair üretir / saklar
* public key’i server’a register eder
* mesajı E2EE şifreler
* gelen paketi çözer
* UI’a basar

---

### 2.1 Kullanıcı Adı ve Logout

```js
const username = (localStorage.getItem("username") || "").trim();
```

* index sayfasında girilen `username` localStorage’a yazıldığı için buradan okunur
* yoksa `/` sayfasına döner

Logout:

* localStorage temizlenir
* `/` sayfasına yönlendirilir

---

### 2.2 Base64 Dönüşümleri (`abToB64`, `b64ToAb`)

WebCrypto encrypt/decrypt işlemleri `ArrayBuffer` döndürür.
JSON paketine koymak için base64’e çeviriyoruz:

* `abToB64`: ArrayBuffer → base64 string
* `b64ToAb`: base64 string → ArrayBuffer

---

### 2.3 IndexedDB (Key Saklama)

Amaç:

* RSA keypair tarayıcı kapansa bile kalsın.

Fonksiyonlar:

* `openDB()` → `e2ee_chat_db` adlı IndexedDB açar, yoksa `keys` store oluşturur
* `idbGet(username)` → bu kullanıcıya ait key kaydını çeker
* `idbPut(record)` → key kaydını yazar

---

### 2.4 RSA Keypair Üretme (`ensureKeypair`)

* IndexedDB’de varsa keypair’i döner
* yoksa:

  * `crypto.subtle.generateKey(...)` ile **RSA-OAEP** keypair üretir
  * `extractable=false` → private key export edilemez
  * IndexedDB’ye kaydeder
  * `{ privateKey, publicKey }` döner

---

### 2.5 Public Key Register (`registerMyPublicKey`)

Adımlar:

* public key `spki` formatında export edilir
* SPKI bytes base64’e çevrilir
* PEM formatına dönüştürülür
* `POST /register_key` ile `{ username, public_key_pem }` server’a gönderilir

---

### 2.6 Başkasının Public Key’ini Alma (`fetchUserPublicKey`)

Adımlar:

* `GET /public_key/{username}` ile PEM alınır
* PEM içinden base64 kısmı temizlenir
* `crypto.subtle.importKey("spki", ...)` ile WebCrypto public key’e çevrilir
* bu key yalnızca **encrypt** amaçlı kullanılır

---

### 2.7 Mesaj Paket Üretimi (`makePacket`)

Bu fonksiyon plaintext mesajı alır ve server’a gönderilecek paketi üretir.

Adımlar:

* AES-GCM 256-bit key üretilir
* IV üretilir
* plaintext AES-GCM ile şifrelenir → `ct`
* AES key raw export edilir
* AES raw key:

  * alıcının public key’i ile RSA-OAEP encrypt → `encKeyTo`
  * göndericinin public key’i ile RSA-OAEP encrypt → `encKeyFrom`

Paket:

* `from`, `to`
* `iv_b64`, `ct_b64`
* `enc_key_to_b64`, `enc_key_from_b64`

---

### 2.8 Paket Çözme (`openPacket`)

Adımlar:

* hangi AES key kullanılacak seçilir:

  * `packet.from === myUsername` ise → `enc_key_from_b64` (kendi mesajın)
  * değilse → `enc_key_to_b64` (gelen mesaj)
* seçilen `enc_key` private key ile RSA-OAEP decrypt edilir → `aesRaw`
* `aesRaw` tekrar AES-GCM key olarak import edilir
* `iv` ve `ct` ile AES-GCM decrypt yapılır
* plaintext string döner

---

### 2.9 Socket Bağlanma ve Eventler

Bağlanma:

```js
const socket = io("http://127.0.0.1:8000", { auth: { username } });
```

* `auth.username`, backend’de `connect(sid, environ, auth)` içine gelir

Eventler:

* `users`: online kullanıcı listesi gelir ve UI’a basılır
* `history_packets`: DB’den gelen eski paketler gelir, decrypt edilip ekrana basılır
* `new_packet`: yeni paket gelir, decrypt edilip ekrana basılır

Gönderme (form submit):

* seçili kullanıcıdan public key çekilir
* `makePacket()` ile paket üretilir
* `socket.emit("send_message", packet)` ile server’a gönderilir

```

```
