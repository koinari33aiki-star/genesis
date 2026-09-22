"""
Genesis License Server v2.0
クライアント（license_manager.py v3.1）に完全対応
"""
import os
import sqlite3
import secrets
from datetime import datetime, date, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn


# ============ Config ============
ADMIN_KEY = os.environ.get("ADMIN_KEY", "CHANGE_ME_NOW")
DB_PATH = os.environ.get(
    "DB_PATH",
    "/data/licenses.db" if os.path.isdir("/data") else "licenses.db"
)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8000))


app = FastAPI(title="Genesis License Server", version="2.0")


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


class AdminReq(BaseModel):
    admin_secret: str = ""
    license_key: Optional[str] = None
    expiry: Optional[str] = None
    max_launches: int = 0
    count: int = 1
    note: str = ""
    active: Optional[bool] = None


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


def check_admin(secret: str):
    if not ADMIN_KEY or secret != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


def make_key():
    seg = lambda: secrets.token_hex(2).upper()
    return f"GEN-{seg()}-{seg()}-{seg()}-{seg()}"


def row_to_dict(row):
    """licenses テーブルの行をクライアント期待の形式に変換"""
    if row is None:
        return None
    d = dict(row)
    return {
        "license_key": d.get("key", ""),
        "hwid": d.get("hwid"),
        "expiry": d.get("expiry"),
        "max_launches": d.get("max_launches", 0),
        "launch_count": d.get("launch_count", 0),
        "active": d.get("status") == "active",
        "note": d.get("note") or "",
        "created_at": d.get("created_at"),
    }


# ============ Client Endpoints ============
@app.get("/")
def root():
    return {"ok": True, "status": "ok", "service": "Genesis License Server"}


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


# ============ Admin Endpoints (クライアント v3.1 対応) ============

@app.post("/admin/generate")
def admin_generate(req: AdminReq):
    """キー発行（複数対応）"""
    check_admin(req.admin_secret)

    count = max(1, min(req.count, 100))
    expiry = req.expiry or "permanent"
    keys = []

    conn = get_db()
    c = conn.cursor()
    for _ in range(count):
        key = make_key()
        c.execute(
            "INSERT INTO licenses (key, hwid, expiry, max_launches, "
            "launch_count, status, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (key, None, expiry, req.max_launches, 0, "active",
             req.note, now_str())
        )
        keys.append(key)
    conn.commit()
    conn.close()

    return {"ok": True, "keys": keys, "count": len(keys)}


@app.post("/admin/list")
def admin_list(req: AdminReq):
    """全キー一覧"""
    check_admin(req.admin_secret)

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()

    return {"ok": True, "licenses": [row_to_dict(r) for r in rows]}


@app.post("/admin/revoke")
def admin_revoke(req: AdminReq):
    """キー停止"""
    check_admin(req.admin_secret)
    if not req.license_key:
        return {"ok": False, "reason": "license_key が必要です"}

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
    return {"ok": True, "reason": "キーを停止しました"}


@app.post("/admin/unrevoke")
def admin_unrevoke(req: AdminReq):
    """キー再開"""
    check_admin(req.admin_secret)
    if not req.license_key:
        return {"ok": False, "reason": "license_key が必要です"}

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET status = 'active' WHERE key = ?",
              (req.license_key,))
    if c.rowcount == 0:
        conn.close()
        return {"ok": False, "reason": "キーが見つかりません"}
    conn.commit()
    conn.close()
    return {"ok": True, "reason": "キーを再開しました"}


@app.post("/admin/set_expiry")
def admin_set_expiry(req: AdminReq):
    """期限変更"""
    check_admin(req.admin_secret)
    if not req.license_key:
        return {"ok": False, "reason": "license_key が必要です"}

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET expiry = ? WHERE key = ?",
              (req.expiry or "permanent", req.license_key))
    if c.rowcount == 0:
        conn.close()
        return {"ok": False, "reason": "キーが見つかりません"}
    conn.commit()
    conn.close()
    return {"ok": True, "reason": "期限を変更しました"}


@app.post("/admin/reset_hwid")
def admin_reset_hwid(req: AdminReq):
    """HWIDリセット"""
    check_admin(req.admin_secret)
    if not req.license_key:
        return {"ok": False, "reason": "license_key が必要です"}

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE licenses SET hwid = NULL WHERE key = ?", (req.license_key,))
    if c.rowcount == 0:
        conn.close()
        return {"ok": False, "reason": "キーが見つかりません"}
    c.execute("DELETE FROM sessions WHERE license_key = ?", (req.license_key,))
    conn.commit()
    conn.close()
    return {"ok": True, "reason": "HWIDをリセットしました"}


@app.post("/admin/delete")
def admin_delete(req: AdminReq):
    """完全削除"""
    check_admin(req.admin_secret)
    if not req.license_key:
        return {"ok": False, "reason": "license_key が必要です"}

    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE key = ?", (req.license_key,))
    c.execute("DELETE FROM sessions WHERE license_key = ?", (req.license_key,))
    conn.commit()
    conn.close()
    return {"ok": True, "reason": "削除しました"}


@app.post("/admin/info")
def admin_info(req: AdminReq):
    """キー情報"""
    check_admin(req.admin_secret)
    if not req.license_key:
        return {"ok": False, "reason": "license_key が必要です"}

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE key = ?", (req.license_key,))
    row = c.fetchone()
    conn.close()

    if not row:
        return {"ok": False, "reason": "キーが見つかりません"}

    return {"ok": True, **row_to_dict(row)}


# ============ 旧エンドポイント互換（curl で使う用） ============
# ヘッダー x-admin-key でも動くようにしておく

from fastapi import Header

@app.post("/admin/create")
def admin_create_legacy(req: AdminReq, x_admin_key: Optional[str] = Header(None)):
    """旧クライアント互換・単一キー発行"""
    secret = req.admin_secret or (x_admin_key or "")
    check_admin(secret)

    key = make_key()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (key, hwid, expiry, max_launches, "
        "launch_count, status, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (key, None, req.expiry or "permanent", req.max_launches, 0,
         "active", req.note, now_str())
    )
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "license_key": key,
        "expiry": req.expiry or "permanent",
        "max_launches": req.max_launches,
    }


if __name__ == "__main__":
    uvicorn.run("server:app", host=HOST, port=PORT)
