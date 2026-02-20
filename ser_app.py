import socketio
import hashlib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy import select, or_
from db import SessionLocal, engine, Base
from models import Message
Base.metadata.create_all(bind=engine)
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
api = FastAPI()
api.mount("/static",StaticFiles(directory="static"),name="static")
templates = Jinja2Templates(directory="templates")
ONLINE: dict[str,str] = {}
PUBLIC_KEYS: dict[str,str] = {}
def pem_fingerprint_sha256(pub_pem: str) -> str:
    """
    PEM string -> SHA-256 hex fingerprint
    Not: Basitlik için PEM'in bytes'ını hashliyoruz (SPKI DER'e çevirmek daha temizdir ama şimdilik yeter)
    """
    data = pub_pem.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
class RegısterKeyIn(BaseModel):
    username: str
    public_key_pem:str
#-> anahtar
@api.post("/register_key")
def register_key(data:RegısterKeyIn):
    username = data.username.strip()
    if not username:
        raise HTTPException(400, "username boş olamaz")
    pub = data.public_key_pem.strip()
    if "BEGIN PUBLIC KEY" not in pub:
        raise HTTPException(400, "public_key_pem PEM formatında değil")
    PUBLIC_KEYS[username] = pub
    fp = pem_fingerprint_sha256(pub)
    return {"ok": True, "fingerprint": fp}
@api.get("/public_key/{username}")
def get_public_key(username: str):
    username = username.strip()
    pub = PUBLIC_KEYS.get(username)
    if not pub:
        raise HTTPException(404, "key not found")
    fp = pem_fingerprint_sha256(pub)
    return {"username": username, "public_key_pem": pub, "fingerprint": fp}

# -> Sayfalar
@api.get("/",response_class=HTMLResponse)
async def index(request : Request):
    return templates.TemplateResponse("index.html",{"request":request})


@api.get("/chat",response_class=HTMLResponse)
async def chat(request:Request):
    return templates.TemplateResponse("chat.html", {"request": request})




@sio.event
async def connect(sid,environ,auth):
    db = SessionLocal()
    auth = auth if isinstance(auth,dict) else {}
    username = (auth.get("username") or "").strip()
    if not username:
        return False
    if username in ONLINE:
        return False
    ONLINE[username] = sid
    try:
        rows = db.execute(
            select(Message)
            .where(or_(Message.from_user == username, Message.to_user == username))
            .order_by(Message.id.desc())
            .limit(50)
        ).scalars().all()
    finally:
        db.close()

    rows.reverse()  # eski -> yeni sıraya çevir
    history_packets = []
    for m in rows:
        history_packets.append({
            "from": m.from_user,
            "to": m.to_user,
            "iv_b64": m.iv_b64,
            "ct_b64": m.ct_b64,
            "enc_key_to_b64": m.enc_key_to_b64,
            "enc_key_from_b64": m.enc_key_from_b64,
            "created_at": m.created_at.isoformat(),
        })
    await sio.save_session(sid,{"username":username})
    await sio.emit("users",list(ONLINE.keys()))
    await sio.emit("history_packets", history_packets, to=sid)
    print("connect:", username, sid)
    return True
@sio.event
async def disconnect(sid):
    sess = await sio.get_session(sid)
    username = (sess.get("username") or "").strip()

    if username and ONLINE.get(username) == sid:
        ONLINE.pop(username, None)

    await sio.emit("users", list(ONLINE.keys()))
    print("disconnect:", username or "anon", sid)

@sio.event
async def send_packet(sid, packet):
    sess = await sio.get_session(sid)
    sender = (sess.get("username") or "").strip()
    if not sender:
        return
    if not isinstance(packet,dict):
        return
    required = ("from","to","iv_b64","ct_b64","enc_key_to_b64","enc_key_from_b64")
    for r in required:
        if r not in packet:
            return 
    if (packet.get("from") or "").strip() != sender:
        print("spoof blocked:", sender, packet.get("from"))
        return
    to_user = (packet.get("to") or "").strip()
    if not to_user:
        return
    if (
    len(packet.get("ct_b64", "")) > 50000
    or len(packet.get("enc_key_to_b64", "")) > 10000
    or len(packet.get("enc_key_from_b64", "")) > 10000
):
        return
    now = datetime.utcnow()
    packet["created_at"] = now.isoformat()
    db = SessionLocal()
    try:
        db.add(
            Message(
                from_user=packet["from"].strip(),
                to_user=packet["to"].strip(),
                iv_b64=packet["iv_b64"],
                ct_b64=packet["ct_b64"],
                enc_key_to_b64=packet["enc_key_to_b64"],
                enc_key_from_b64=packet["enc_key_from_b64"],
                created_at=now,
            )
        )
        db.commit()
    finally:
        db.close()
    to_sid = ONLINE.get(to_user)
    if to_sid:
        await sio.emit("new_packet",packet,to=to_sid)
    await sio.emit("new_packet",packet,to=sid)

    


# birleşik ASGI app (FastAPI + Socket.IO)
app = socketio.ASGIApp(sio, other_asgi_app=api)    