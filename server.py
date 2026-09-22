"""
Genesis License Server
Deploy on Render.com
"""
import os
import sqlite3
import secrets
from datetime import datetime, date, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import uvicorn


# ============ Config ============
ADMIN_KEY = os.environ.get("ADMIN_KEY", "CHANGE_ME_NOW")
# Render の Persistent Disk は /data にマウントされる想定
DB_PATH = os.environ.get(
    "DB_PATH",
    "/data/licenses.db" if os.path.isdir("/data") else "licenses.db"
)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8000))


app = FastAPI(title="Genesis License Server", version="1.0")


# ============ Database ============
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            expiry TEXT,
            max_launches INTEGER DEFAULT 0,
            launch_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            note TEXT,
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            license_key TEXT NOT NULL,
            hwid TEXT NOT NULL,
            created_at TEXT,
            last_seen TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ============ Models ============
class ActivateReq(BaseModel):
    license_key: str
    hwid: str


class HeartbeatReq(BaseModel):
    token: str
    hwid: str


class CreateReq(BaseModel):
    days: Optional[int] = 30
    max_launches: int = 0
    note: str = ""


class KeyReq(BaseModel):
    license_key: str


class ExtendReq(BaseModel):
    license_key: str
    days: int


# ============ Helpers ============
def now_str():
    return datetime.utcnow().isoformat()


def is_expired(expiry) -> bool:
    if not expiry or str(expiry).lower() == "permanent":
        return False
    try:
        exp = datetime.strptime(expiry, "%Y-%m-%d").date()
    except ValueError:
        return False
    return exp < date.today()


def check_admin(x_admin_key: str):
    if not ADMIN_KEY or x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


# ============ Client Endpoints ============
@app.get("/")
def root():
    return {"ok": True, "service": "Genesis License Server"}


@app.post("/api/activate")
def activate(req: ActivateReq):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE key = ?", (req.license_key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return {"ok": False, "reason": "ライセンスキーが存在しません"}

    if row["status"] != "active":
        conn.close()
        return {"ok": False, "reason": "ライセンスは無効化されています"}

    if is_expired(row["expiry"]):
        conn.close()
        return {"ok": False, "reason": "ライセンスが期限切れです"}

    # HWID バインド
    if row["hwid"] and row["hwid"] != req.hwid:
        conn.close()
        return {"ok": False,
                "reason": "このキーは別のPCに紐付けられています (HWID不一致)"}

    if row["max_launches"] > 0 and row["launch_count"] >= row["max_launches"]:
        conn.close()
        return {"ok": False, "reason": "起動回数の上限に達しました"}

    new_hwid = row["hwid"] or req.hwid
    new_launch = row["launch_count"] + 1
    token = secrets.token_urlsafe(32)

    c.execute(
        "UPDATE licenses SET hwid = ?, launch_count = ? WHERE key = ?",
        (new_hwid, new_launch, req.license_key)
    )
    c.execute(
        "INSERT INTO sessions (token, license_key, hwid, created_at, last_seen) "
        "VALUES (?, ?, ?, ?, ?)",
        (token, req.license_key, req.hwid, now_str(), now_str())
    )
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "token": token,
        "expiry": row["expiry"],
        "launch_count": new_launch,
        "max_launches": row["max_launches"],
    }


@app.post("/api/heartbeat")
def heartbeat(req: HeartbeatReq):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE token = ?", (req.token,))
    sess = c.fetchone()

    if not sess:
        conn.close()
        return {"ok": False, "reason": "セッションが存在しません"}

    if sess["hwid"] != req.hwid:
        c.execute("DELETE FROM sessions WHERE token = ?", (req.token,))
        conn.commit()
        conn.close()
        return {"ok": False, "reason": "HWIDが一致しません"}

    c.execute("SELECT * FROM licenses WHERE key = ?", (sess["license_key"],))
    lic = c.fetchone()

    if not lic:
        c.execute("DELETE FROM sessions WHERE token = ?", (req.token,))
        conn.commit()
        conn.close()
        return {"ok": False, "reason": "ライセンスが存在しません"}

    if lic["status"] != "active":
        c.execute("DELETE FROM sessions WHERE token = ?", (req.token,))
        conn.commit()
        conn.close()
        return {"ok": False, "reason": "ライセンスは無効化されています"}

    if is_expired(lic["expiry"]):
        c.execute("DELETE FROM sessions WHERE token = ?", (req.token,))
        conn.commit()
        conn.close()
        return {"ok": False, "reason": "ライセンスが期限切れです"}

    c.execute("UPDATE sessions SET last_seen = ? WHERE token = ?",
              (now_str(), req.token))
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "expiry": lic["expiry"],
        "launch_count": lic["launch_count"],
        "max_launches": lic["max_launches"],
    }


# ============ Admin Endpoints ============
@app.post("/admin/create")
def admin_create(req: CreateReq, x_admin_key: str = Header(...)):
    check_admin(x_admin_key)

    def seg():
        return secrets.token_hex(2).upper()
    key = f"GEN-{seg()}-{seg()}-{seg()}-{seg()}"

    if req.days is not None and req.days > 0:
        expiry = (date.today() + timedelta(days=req.days)).strftime("%Y-%m-%d")
    else:
        expiry = "permanent"

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (key, hwid, expiry, max_launches, launch_count, "
        "status, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (key, None, expiry, req.max_launches, 0, "active", req.note, now_str())
    )
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "license_key": key,
        "expiry": expiry,
        "max_launches": req.max_launches,
    }


@app.get("/admin/list")
def admin_list(x_admin_key: str = Header(...)):
    check_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses ORDER BY created_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"ok": True, "licenses": rows}


@app.post("/admin/revoke")
def admin_revoke(req: KeyReq, x_admin_key: str = Header(...)):
    check_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET status = 'revoked' WHERE key = ?",
              (req.license_key,))
    if c.rowcount == 0:
        conn.close()
        return {"ok": False, "reason": "キーが見つかりません"}
    c.execute("DELETE FROM sessions WHERE license_key = ?", (req.license_key,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/admin/unrevoke")
def admin_unrevoke(req: KeyReq, x_admin_key: str = Header(...)):
    check_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET status = 'active' WHERE key = ?",
              (req.license_key,))
    if c.rowcount == 0:
        conn.close()
        return {"ok": False, "reason": "キーが見つかりません"}
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/admin/extend")
def admin_extend(req: ExtendReq, x_admin_key: str = Header(...)):
    check_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT expiry FROM licenses WHERE key = ?", (req.license_key,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"ok": False, "reason": "キーが見つかりません"}

    cur = row["expiry"]
    if not cur or str(cur).lower() == "permanent":
        base = date.today()
    else:
        try:
            base = datetime.strptime(cur, "%Y-%m-%d").date()
        except ValueError:
            base = date.today()
        if base < date.today():
            base = date.today()

    new_expiry = (base + timedelta(days=req.days)).strftime("%Y-%m-%d")
    c.execute("UPDATE licenses SET expiry = ? WHERE key = ?",
              (new_expiry, req.license_key))
    conn.commit()
    conn.close()
    return {"ok": True, "expiry": new_expiry}


@app.post("/admin/reset_hwid")
def admin_reset_hwid(req: KeyReq, x_admin_key: str = Header(...)):
    check_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET hwid = NULL WHERE key = ?",
              (req.license_key,))
    if c.rowcount == 0:
        conn.close()
        return {"ok": False, "reason": "キーが見つかりません"}
    c.execute("DELETE FROM sessions WHERE license_key = ?", (req.license_key,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/admin/delete")
def admin_delete(req: KeyReq, x_admin_key: str = Header(...)):
    check_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE key = ?", (req.license_key,))
    c.execute("DELETE FROM sessions WHERE license_key = ?", (req.license_key,))
    conn.commit()
    conn.close()
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run("server:app", host=HOST, port=PORT)
