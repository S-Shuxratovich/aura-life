import os, io, re, hmac, hashlib, json, sqlite3, asyncio, time, secrets, tempfile, shutil
from urllib.parse import parse_qsl
from contextlib import asynccontextmanager
from datetime import datetime

from dotenv import load_dotenv
import aiohttp
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery, WebAppInfo, InlineKeyboardMarkup, InlineKeyboardButton
from anthropic import AsyncAnthropic

load_dotenv()
BOT_TOKEN = os.environ["BOT_TOKEN"]
WEBAPP_URL = os.environ.get("WEBAPP_URL", "")
DB_PATH = os.environ.get("DB_PATH", "life.db")
AI_MODEL = os.environ.get("AI_MODEL", "claude-sonnet-4-6")
DEV = os.environ.get("DEV") == "1"
AISHA_KEY = os.environ.get("AISHA_API_KEY", "")

bot = Bot(BOT_TOKEN)
dp = Dispatcher()
ai = AsyncAnthropic()  # ANTHROPIC_API_KEY ni muhitdan oladi


# ---------- DB ----------
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY, user_id INTEGER, kind TEXT, amount INTEGER,
            category TEXT, note TEXT DEFAULT '', created TEXT);
        CREATE TABLE IF NOT EXISTS tasks(
            id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, time TEXT DEFAULT '',
            done INTEGER DEFAULT 0, created TEXT);
        CREATE TABLE IF NOT EXISTS users(
            user_id INTEGER PRIMARY KEY, pin_hash TEXT, salt TEXT,
            failed INTEGER DEFAULT 0, locked_until REAL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS i_tx ON transactions(user_id, created);
        CREATE INDEX IF NOT EXISTS i_tk ON tasks(user_id);
        """)

def add_tx(uid, kind, amount, category, note=""):
    with db() as c:
        c.execute("INSERT INTO transactions(user_id,kind,amount,category,note,created) VALUES(?,?,?,?,?,?)",
                  (uid, kind, int(amount), category.strip()[:40], note.strip()[:200], datetime.now().isoformat(timespec="seconds")))

def add_task_db(uid, title, time_=""):
    with db() as c:
        c.execute("INSERT INTO tasks(user_id,title,time,created) VALUES(?,?,?,?)",
                  (uid, title.strip()[:200], time_.strip()[:20], datetime.now().isoformat(timespec="seconds")))

def summary(uid):
    month = datetime.now().strftime("%Y-%m")
    with db() as c:
        rows = c.execute("SELECT kind, SUM(amount) s FROM transactions WHERE user_id=? AND created LIKE ? GROUP BY kind",
                         (uid, month + "%")).fetchall()
        tot = {r["kind"]: r["s"] for r in rows}
        cats = c.execute("SELECT category, SUM(amount) s FROM transactions WHERE user_id=? AND kind='expense' AND created LIKE ? "
                         "GROUP BY category ORDER BY s DESC", (uid, month + "%")).fetchall()
        recent = c.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)).fetchall()
        allt = c.execute("SELECT kind, SUM(amount) s FROM transactions WHERE user_id=? GROUP BY kind", (uid,)).fetchall()
    a = {r["kind"]: r["s"] for r in allt}
    return {
        "balance": (a.get("income") or 0) - (a.get("expense") or 0),
        "income": tot.get("income") or 0,
        "expense": tot.get("expense") or 0,
        "categories": [dict(r) for r in cats],
        "recent": [dict(r) for r in recent],
    }


# ---------- Telegram initData tekshiruvi ----------
def auth(init_data: str) -> int:
    if not init_data:
        if DEV:
            return 1
        raise HTTPException(401, "initData yo'q")
    data = dict(parse_qsl(init_data, keep_blank_values=True))
    received = data.pop("hash", "")
    check = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    calc = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, received):
        raise HTTPException(401, "initData noto'g'ri")
    if time.time() - int(data.get("auth_date", 0)) > 86400:
        raise HTTPException(401, "initData eskirgan")
    return json.loads(data["user"])["id"]


# ---------- PIN va sessiya ----------
SESSION_KEY = hashlib.sha256(b"session:" + BOT_TOKEN.encode()).digest()
SESSION_TTL = 1800  # 30 daqiqa

def make_token(uid):
    payload = f"{uid}.{int(time.time()) + SESSION_TTL}"
    return payload + "." + hmac.new(SESSION_KEY, payload.encode(), hashlib.sha256).hexdigest()

def check_token(uid, token):
    try:
        u, exp, sig = token.split(".")
        good = hmac.new(SESSION_KEY, f"{u}.{exp}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, good) and int(u) == uid and int(exp) > time.time()
    except Exception:
        return False

def hash_pin(pin, salt):
    return hashlib.scrypt(pin.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()

def get_user_row(uid):
    with db() as c:
        return c.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone()

def check_pin(uid, pin):
    """To'g'ri bo'lsa jim qaytadi, aks holda HTTPException. 5 ta xatodan keyin bloklaydi."""
    row = get_user_row(uid)
    if not row:
        raise HTTPException(403, "pin_required")
    now = time.time()
    if row["locked_until"] > now:
        raise HTTPException(429, f"Juda ko'p urinish. {int(row['locked_until'] - now) + 1} soniyadan keyin urinib ko'ring.")
    if hmac.compare_digest(hash_pin(pin, bytes.fromhex(row["salt"])), row["pin_hash"]):
        with db() as c:
            c.execute("UPDATE users SET failed=0, locked_until=0 WHERE user_id=?", (uid,))
        return
    failed = row["failed"] + 1
    locked = now + min(300 * 2 ** (failed // 5 - 1), 86400) if failed % 5 == 0 else 0
    with db() as c:
        c.execute("UPDATE users SET failed=?, locked_until=? WHERE user_id=?", (failed, locked, uid))
    left = 5 - failed % 5 if failed % 5 else 0
    raise HTTPException(401, "Noto'g'ri PIN." + (f" Qolgan urinish: {left}" if left else " Vaqtincha bloklandi."))

def tg_user(x_init_data: str = Header("")) -> int:
    return auth(x_init_data)

def user(x_init_data: str = Header(""), x_session: str = Header("")) -> int:
    uid = auth(x_init_data)
    if not get_user_row(uid):
        raise HTTPException(403, "pin_required")
    if not check_token(uid, x_session):
        raise HTTPException(403, "locked")
    return uid


# ---------- Ovoz -> matn (Aisha STT, o'zbek tili) ----------
async def to_wav(raw: bytes) -> bytes:
    """Brauzerdan kelgan webm/mp4 ovozni wav ga o'giradi (ffmpeg kerak)."""
    if not shutil.which("ffmpeg"):
        raise RuntimeError("ffmpeg o'rnatilmagan")
    with tempfile.TemporaryDirectory() as d:
        src, dst = os.path.join(d, "in"), os.path.join(d, "out.wav")
        open(src, "wb").write(raw)
        p = await asyncio.create_subprocess_exec("ffmpeg", "-v", "error", "-i", src, "-ar", "16000", "-ac", "1", dst,
                                                 stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await p.wait()
        if p.returncode != 0 or not os.path.exists(dst):
            raise RuntimeError("audio o'girilmadi")
        return open(dst, "rb").read()

async def transcribe(data: bytes, filename: str) -> str:
    if not AISHA_KEY:
        raise RuntimeError("AISHA_API_KEY yo'q")
    ctype = "audio/wav" if filename.endswith(".wav") else "audio/ogg"
    form = aiohttp.FormData()
    form.add_field("audio", data, filename=filename, content_type=ctype)
    form.add_field("language", "uz")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as s:
        async with s.post("https://back.aisha.group/api/v1/stt/post/", data=form,
                          headers={"X-Api-Key": AISHA_KEY, "Accept-Language": "uz"}) as r:
            if r.status != 200:
                raise RuntimeError(f"STT xato: {r.status}")
            j = await r.json()
    return (j.get("transcript") or "").strip()


# ---------- AI (Claude + tool use) ----------
TOOLS = [
    {"name": "add_transaction",
     "description": "Foydalanuvchining kirim yoki xarajatini yozib qo'yadi. Summa so'mda (UZS). 'ming' = x1000, 'mln' = x1 000 000.",
     "input_schema": {"type": "object", "properties": {
         "kind": {"type": "string", "enum": ["income", "expense"]},
         "amount": {"type": "integer"},
         "category": {"type": "string", "description": "Masalan: Ovqatlanish, Transport, Ish haqi, Kommunal"},
         "note": {"type": "string"}}, "required": ["kind", "amount", "category"]}},
    {"name": "add_task",
     "description": "Yangi reja yoki vazifa qo'shadi.",
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"},
         "time": {"type": "string", "description": "Vaqt, masalan 15:00 yoki 10:00-12:00"}}, "required": ["title"]}},
    {"name": "get_summary",
     "description": "Joriy oy kirim/xarajat, umumiy balans va kategoriyalar bo'yicha xulosani qaytaradi.",
     "input_schema": {"type": "object", "properties": {}}},
]

SYSTEM = ("Sen 'Life Manager' ilovasining shaxsiy yordamchisisan. O'zbek tilida (lotin), qisqa va samimiy javob ber. "
          "Foydalanuvchi xarajat/kirim yoki reja aytsa, tegishli vositani chaqir, so'ng nima yozilganini bir jumlada tasdiqla. "
          "Moliyaviy savollarda get_summary dan foydalan, raqamlarni o'ylab topma. Bugungi sana: {today}.")

def run_tool(uid, name, args):
    if name == "add_transaction":
        add_tx(uid, args["kind"], args["amount"], args["category"], args.get("note", ""))
        return "Yozildi."
    if name == "add_task":
        add_task_db(uid, args["title"], args.get("time", ""))
        return "Reja qo'shildi."
    if name == "get_summary":
        s = summary(uid)
        return json.dumps({k: s[k] for k in ("balance", "income", "expense", "categories")}, ensure_ascii=False)
    return "Noma'lum vosita."

async def ai_chat(uid: int, text: str, allow_read: bool = True):
    tools = TOOLS if allow_read else [t for t in TOOLS if t["name"] != "get_summary"]
    sysmsg = SYSTEM.format(today=datetime.now().strftime("%Y-%m-%d"))
    if not allow_read:
        sysmsg += " Bu kanalda foydalanuvchi ma'lumotlarini ko'rsatma. Hisobot so'ralsa, ilovani ochib PIN kiritishni ayt."
    messages = [{"role": "user", "content": text}]
    changed = False
    for _ in range(5):
        resp = await ai.messages.create(
            model=AI_MODEL, max_tokens=1000, tools=tools, system=sysmsg, messages=messages)
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text") or "Tayyor.", changed
        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                if b.name != "get_summary":
                    changed = True
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": run_tool(uid, b.name, b.input)})
        messages.append({"role": "user", "content": results})
    return "Kechirasiz, buni bajara olmadim.", changed


# ---------- Telegram bot ----------
@dp.message(CommandStart())
async def start(m: Message):
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="📱 Ilovani ochish", web_app=WebAppInfo(url=WEBAPP_URL))]])
    await m.answer("Salom! Men sening shaxsiy hayot menejeringman.\n"
                   "Menga shunchaki yoz: «taksiga 30 ming sarfladim» yoki «ertaga 10:00 da uchrashuv».", reply_markup=kb)

@dp.message(F.text)
async def on_text(m: Message):
    await bot.send_chat_action(m.chat.id, "typing")
    try:
        reply, _ = await ai_chat(m.from_user.id, m.text, allow_read=False)
    except Exception as e:
        print("AI xato:", e)
        reply = "AI hozir javob bera olmadi, birozdan keyin urinib ko'r."
    await m.answer(reply)


@dp.message(F.voice | F.audio)
async def on_voice(m: Message):
    v = m.voice or m.audio
    if (v.duration or 0) > 60:
        return await m.answer("Ovozli xabar 60 soniyadan oshmasin.")
    await bot.send_chat_action(m.chat.id, "typing")
    try:
        buf = io.BytesIO()
        await bot.download(v, destination=buf)
        text = await transcribe(buf.getvalue(), "voice.ogg")
        if not text:
            return await m.answer("Ovozni tushunmadim, qayta aytib ko'ring.")
        await m.answer(f"🎙 «{text}»")  # foydalanuvchi xatoni ko'rib turishi uchun
        reply, _ = await ai_chat(m.from_user.id, text, allow_read=False)
    except Exception as e:
        print("Ovoz xato:", e)
        reply = "Ovozni qayta ishlab bo'lmadi, birozdan keyin urinib ko'ring."
    await m.answer(reply)

@dp.message(Command("resetpin"))
async def resetpin(m: Message):
    kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(
        text="🗑 Ha, PIN va barcha ma'lumotlarni o'chir", callback_data="wipe")]])
    await m.answer("PIN-kodni tiklab bo'lmaydi. Unutgan bo'lsangiz, faqat PIN bilan birga BARCHA ma'lumotlaringiz "
                   "(xarajatlar, rejalar) o'chiriladi. Davom etasizmi?", reply_markup=kb)

@dp.callback_query(F.data == "wipe")
async def wipe(cq: CallbackQuery):
    with db() as c:
        for t in ("transactions", "tasks", "users"):
            c.execute(f"DELETE FROM {t} WHERE user_id=?", (cq.from_user.id,))
    await cq.message.edit_text("Hammasi o'chirildi. Ilovani qayta ochib yangi PIN o'rnating.")
    await cq.answer()


# ---------- API ----------
@asynccontextmanager
async def lifespan(_):
    init_db()
    task = asyncio.create_task(dp.start_polling(bot))
    yield
    task.cancel()
    await bot.session.close()

app = FastAPI(lifespan=lifespan)

class TxIn(BaseModel):
    kind: str
    amount: int
    category: str
    note: str = ""

class TaskIn(BaseModel):
    title: str
    time: str = ""

class AiIn(BaseModel):
    message: str

class PinIn(BaseModel):
    pin: str

class PinSet(BaseModel):
    pin: str
    old_pin: str = ""

@app.get("/api/pin/status")
def pin_status(uid: int = Depends(tg_user)):
    return {"has_pin": bool(get_user_row(uid))}

@app.post("/api/pin/verify")
def pin_verify(b: PinIn, uid: int = Depends(tg_user)):
    check_pin(uid, b.pin)
    return {"token": make_token(uid)}

@app.post("/api/pin/set")
def pin_set(b: PinSet, uid: int = Depends(tg_user)):
    if not re.fullmatch(r"\d{4,6}", b.pin):
        raise HTTPException(400, "PIN 4-6 ta raqamdan iborat bo'lishi kerak")
    if get_user_row(uid):
        check_pin(uid, b.old_pin)  # almashtirish uchun eski PIN shart
    salt = secrets.token_bytes(16)
    with db() as c:
        c.execute("INSERT INTO users(user_id,pin_hash,salt) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
                  "pin_hash=excluded.pin_hash, salt=excluded.salt, failed=0, locked_until=0",
                  (uid, hash_pin(b.pin, salt), salt.hex()))
    return {"token": make_token(uid)}

@app.get("/api/summary")
def get_summary(uid: int = Depends(user)):
    return summary(uid)

@app.post("/api/transactions")
def post_tx(b: TxIn, uid: int = Depends(user)):
    if b.kind not in ("income", "expense") or not (0 < b.amount < 10**12):
        raise HTTPException(400, "Noto'g'ri ma'lumot")
    add_tx(uid, b.kind, b.amount, b.category or "Boshqa", b.note)
    return {"ok": True}

@app.get("/api/tasks")
def get_tasks(uid: int = Depends(user)):
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM tasks WHERE user_id=? ORDER BY done, time, id", (uid,))]

@app.post("/api/tasks")
def post_task(b: TaskIn, uid: int = Depends(user)):
    add_task_db(uid, b.title, b.time)
    return {"ok": True}

@app.post("/api/tasks/{tid}/toggle")
def toggle_task(tid: int, uid: int = Depends(user)):
    with db() as c:
        c.execute("UPDATE tasks SET done = 1 - done WHERE id=? AND user_id=?", (tid, uid))
    return {"ok": True}

@app.delete("/api/tasks/{tid}")
def del_task(tid: int, uid: int = Depends(user)):
    with db() as c:
        c.execute("DELETE FROM tasks WHERE id=? AND user_id=?", (tid, uid))
    return {"ok": True}

@app.post("/api/ai")
async def post_ai(b: AiIn, uid: int = Depends(user)):
    reply, changed = await ai_chat(uid, b.message[:1000], allow_read=True)
    return {"reply": reply, "changed": changed}

@app.post("/api/voice")
async def post_voice(request: Request, uid: int = Depends(user)):
    raw = await request.body()
    if not raw or len(raw) > 5_000_000:
        raise HTTPException(400, "Audio hajmi noto'g'ri")
    try:
        text = await transcribe(await to_wav(raw), "voice.wav")
    except Exception as e:
        print("Ovoz xato:", e)
        raise HTTPException(502, "Ovozni o'qib bo'lmadi")
    return {"text": text}

app.mount("/", StaticFiles(directory="webapp", html=True), name="webapp")
