import os
import re
import hmac
import json
import time
import hashlib
import secrets
import logging
from functools import wraps
from datetime import datetime, timedelta, timezone

import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, jsonify, g

# =========================================================
# MASIH GRAM - CENTRAL BACKEND
# Python / Flask / PostgreSQL / Render
# =========================================================

APP_NAME = "MASIH GRAM"
API_VERSION = "v1"

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("masih-gram")

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
OTP_SECRET = os.getenv("OTP_SECRET", "").strip()
KAVENEGAR_API_KEY = os.getenv("KAVENEGAR_API_KEY", "").strip()
KAVENEGAR_TEMPLATE = os.getenv("KAVENEGAR_TEMPLATE", "").strip()

DB_SSLMODE = os.getenv("DB_SSLMODE", "require")
OTP_LIFETIME_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_SECONDS = 60
OTP_MAX_PER_HOUR = 5
SESSION_DAYS = 30

# =========================================================
# DATABASE
# =========================================================

def db_connect():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")

    return psycopg2.connect(
        DATABASE_URL,
        sslmode=DB_SSLMODE,
        connect_timeout=15
    )


def db_query(sql, params=None, fetchone=False, fetchall=False,
             commit=False):
    conn = db_connect()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(sql, params or ())

        result = None
        if fetchone:
            result = cur.fetchone()
        elif fetchall:
            result = cur.fetchall()

        if commit:
            conn.commit()
        else:
            conn.commit()

        cur.close()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database():
    statements = [

        """
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            phone VARCHAR(20) UNIQUE NOT NULL,
            display_name VARCHAR(80) NOT NULL DEFAULT '',
            username VARCHAR(32) UNIQUE,
            bio VARCHAR(300) NOT NULL DEFAULT '',
            avatar_url TEXT,
            is_verified BOOLEAN NOT NULL DEFAULT FALSE,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen TIMESTAMPTZ
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS otp_challenges (
            id BIGSERIAL PRIMARY KEY,
            phone VARCHAR(20) NOT NULL,
            code_hash VARCHAR(128) NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            consumed_at TIMESTAMPTZ
        )
        """,

        """
        CREATE INDEX IF NOT EXISTS idx_otp_phone_created
        ON otp_challenges(phone, created_at DESC)
        """,

        """
        CREATE TABLE IF NOT EXISTS sessions (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            token_hash VARCHAR(128) UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            revoked_at TIMESTAMPTZ
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS conversations (
            id BIGSERIAL PRIMARY KEY,
            title VARCHAR(100) NOT NULL DEFAULT '',
            type VARCHAR(20) NOT NULL DEFAULT 'private',
            owner_id BIGINT REFERENCES users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS conversation_members (
            conversation_id BIGINT NOT NULL REFERENCES conversations(id)
                ON DELETE CASCADE,
            user_id BIGINT NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            role VARCHAR(20) NOT NULL DEFAULT 'member',
            joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_read_message_id BIGINT,
            PRIMARY KEY (conversation_id, user_id)
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS messages (
            id BIGSERIAL PRIMARY KEY,
            conversation_id BIGINT NOT NULL
                REFERENCES conversations(id) ON DELETE CASCADE,
            sender_id BIGINT NOT NULL REFERENCES users(id),
            message_type VARCHAR(20) NOT NULL DEFAULT 'text',
            body TEXT NOT NULL DEFAULT '',
            reply_to BIGINT REFERENCES messages(id),
            edited_at TIMESTAMPTZ,
            deleted_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,

        """
        CREATE INDEX IF NOT EXISTS idx_messages_conversation
        ON messages(conversation_id, id DESC)
        """,

        """
        CREATE TABLE IF NOT EXISTS message_receipts (
            message_id BIGINT NOT NULL REFERENCES messages(id)
                ON DELETE CASCADE,
            user_id BIGINT NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            delivered_at TIMESTAMPTZ,
            read_at TIMESTAMPTZ,
            PRIMARY KEY (message_id, user_id)
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS contacts (
            owner_id BIGINT NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            contact_user_id BIGINT NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (owner_id, contact_user_id)
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS stories (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            media_url TEXT NOT NULL,
            caption VARCHAR(500) NOT NULL DEFAULT '',
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS story_views (
            story_id BIGINT NOT NULL REFERENCES stories(id)
                ON DELETE CASCADE,
            viewer_id BIGINT NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (story_id, viewer_id)
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS call_sessions (
            id BIGSERIAL PRIMARY KEY,
            conversation_id BIGINT REFERENCES conversations(id),
            caller_id BIGINT NOT NULL REFERENCES users(id),
            receiver_id BIGINT NOT NULL REFERENCES users(id),
            call_type VARCHAR(10) NOT NULL DEFAULT 'audio',
            status VARCHAR(20) NOT NULL DEFAULT 'ringing',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            ended_at TIMESTAMPTZ
        )
        """
    ]

    conn = db_connect()
    try:
        cur = conn.cursor()
        for sql in statements:
            cur.execute(sql)
        conn.commit()
        cur.close()
        logger.info("MASIH GRAM database initialized")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# =========================================================
# COMMON HELPERS
# =========================================================

def response(data=None, message="OK", status=200):
    return jsonify({
        "success": status < 400,
        "message": message,
        "data": data
    }), status


def error(message, status=400):
    return response(None, message, status)


def now_utc():
    return datetime.now(timezone.utc)


def normalize_iran_phone(value):
    if not isinstance(value, str):
        return None

    value = value.strip()
    persian = "۰۱۲۳۴۵۶۷۸۹"
    arabic = "٠١٢٣٤٥٦٧٨٩"

    for i in range(10):
        value = value.replace(persian[i], str(i))
        value = value.replace(arabic[i], str(i))

    value = re.sub(r"[\s\-\(\)]", "", value)

    if value.startswith("0098"):
        value = "+98" + value[4:]
    elif value.startswith("98"):
        value = "+" + value
    elif value.startswith("09"):
        value = "+98" + value[1:]

    if not re.fullmatch(r"\+989\d{9}", value):
        return None

    return value


def hash_value(value):
    secret = OTP_SECRET or "NOT_CONFIGURED"
    return hmac.new(
        secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return error("برای استفاده از این بخش وارد حساب شوید.", 401)

        token = header[7:].strip()
        if not token:
            return error("توکن معتبر نیست.", 401)

        token_digest = hash_token(token)

        row = db_query(
            """
            SELECT u.id, u.phone, u.display_name, u.username,
                   u.bio, u.avatar_url
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = %s
              AND s.revoked_at IS NULL
              AND s.expires_at > NOW()
              AND u.is_active = TRUE
            LIMIT 1
            """,
            (token_digest,),
            fetchone=True
        )

        if not row:
            return error("نشست شما منقضی شده است. دوباره وارد شوید.", 401)

        g.user = row
        g.user_id = row["id"]
        return fn(*args, **kwargs)

    return wrapper


def create_session(user_id):
    token = secrets.token_urlsafe(48)
    db_query(
        """
        INSERT INTO sessions(user_id, token_hash, expires_at)
        VALUES(%s, %s, NOW() + INTERVAL '30 days')
        """,
        (user_id, hash_token(token)),
        commit=True
    )
    return token


def public_user(user):
    return {
        "id": user["id"],
        "phone": user.get("phone"),
        "display_name": user.get("display_name", ""),
        "username": user.get("username"),
        "bio": user.get("bio", ""),
        "avatar_url": user.get("avatar_url")
    }


# =========================================================
# SMS / OTP
# =========================================================

def send_kavenegar_otp(phone, code):
    if not KAVENEGAR_API_KEY or not KAVENEGAR_TEMPLATE:
        raise RuntimeError("Kavenegar is not configured")

    receptor = "0" + phone[3:]

    url = (
        "https://api.kavenegar.com/v1/"
        + KAVENEGAR_API_KEY
        + "/verify/lookup.json"
    )

    result = requests.get(
        url,
        params={
            "receptor": receptor,
            "token": code,
            "template": KAVENEGAR_TEMPLATE,
            "type": "sms"
        },
        timeout=15
    )

    result.raise_for_status()
    payload = result.json()

    entries = payload.get("entries") or []
    if not entries:
        raise RuntimeError("Kavenegar returned an empty response")

    status_code = entries[0].get("status")
    if status_code not in (1, 2, 4, 5, 10, 200):
        raise RuntimeError("Kavenegar rejected the SMS request")

    return True


@app.post("/api/v1/auth/request-otp")
def request_otp():
    data = get_json()
    phone = normalize_iran_phone(data.get("phone", ""))

    if not phone:
        return error("شماره موبایل ایران معتبر نیست. نمونه: 09123456789")

    if not OTP_SECRET or not KAVENEGAR_API_KEY or not KAVENEGAR_TEMPLATE:
        return error("تنظیمات پیامک سرور کامل نشده است.", 503)

    recent = db_query(
        """
        SELECT created_at
        FROM otp_challenges
        WHERE phone = %s
          AND created_at > NOW() - INTERVAL '60 seconds'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (phone,),
        fetchone=True
    )

    if recent:
        return error("برای ارسال دوباره کد، کمی صبر کنید.", 429)

    count_row = db_query(
        """
        SELECT COUNT(*) AS total
        FROM otp_challenges
        WHERE phone = %s
          AND created_at > NOW() - INTERVAL '1 hour'
        """,
        (phone,),
        fetchone=True
    )

    if count_row and count_row["total"] >= OTP_MAX_PER_HOUR:
        return error("تعداد درخواست‌های پیامک بیش از حد مجاز است.", 429)

    code = f"{secrets.randbelow(1000000):06d}"
    code_digest = hash_value(phone + ":" + code)

    try:
        send_kavenegar_otp(phone, code)
    except Exception as exc:
        logger.exception("SMS sending failed: %s", exc)
        return error("ارسال پیامک انجام نشد. تنظیمات پنل پیامکی را بررسی کنید.", 502)

    db_query(
        """
        INSERT INTO otp_challenges(phone, code_hash, expires_at)
        VALUES(%s, %s, NOW() + INTERVAL '5 minutes')
        """,
        (phone, code_digest),
        commit=True
    )

    return response({
        "phone": phone,
        "expires_in": OTP_LIFETIME_SECONDS,
        "resend_after": OTP_RESEND_SECONDS
    }, "کد ورود ارسال شد.")


@app.post("/api/v1/auth/verify-otp")
def verify_otp():
    data = get_json()
    phone = normalize_iran_phone(data.get("phone", ""))
    code = str(data.get("code", "")).strip()

    if not phone:
        return error("شماره موبایل معتبر نیست.")

    if not re.fullmatch(r"\d{6}", code):
        return error("کد ورود باید ۶ رقم باشد.")

    conn = db_connect()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute(
            """
            SELECT id, code_hash, attempts
            FROM otp_challenges
            WHERE phone = %s
              AND consumed_at IS NULL
              AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            FOR UPDATE
            """,
            (phone,)
        )
        challenge = cur.fetchone()

        if not challenge:
            conn.rollback()
            return error("کد وجود ندارد یا منقضی شده است.", 400)

        if challenge["attempts"] >= OTP_MAX_ATTEMPTS:
            conn.rollback()
            return error("تعداد تلاش‌ها بیش از حد مجاز است.", 429)

        expected = hash_value(phone + ":" + code)
        valid = hmac.compare_digest(
            challenge["code_hash"],
            expected
        )

        if not valid:
            cur.execute(
                """
                UPDATE otp_challenges
                SET attempts = attempts + 1
                WHERE id = %s
                """,
                (challenge["id"],)
            )
            conn.commit()
            return error("کد ورود اشتباه است.", 400)

        cur.execute(
            """
            UPDATE otp_challenges
            SET consumed_at = NOW()
            WHERE id = %s
            """,
            (challenge["id"],)
        )

        cur.execute(
            """
            INSERT INTO users(phone, is_verified)
            VALUES(%s, TRUE)
            ON CONFLICT(phone)
            DO UPDATE SET
                is_verified = TRUE,
                updated_at = NOW()
            RETURNING id, phone, display_name, username, bio, avatar_url
            """,
            (phone,)
        )
        user = cur.fetchone()

        token = secrets.token_urlsafe(48)
        cur.execute(
            """
            INSERT INTO sessions(user_id, token_hash, expires_at)
            VALUES(%s, %s, NOW() + INTERVAL '30 days')
            """,
            (user["id"], hash_token(token))
        )

        conn.commit()

        return response({
            "token": token,
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": SESSION_DAYS * 24 * 60 * 60,
            "user": public_user(user)
        }, "ورود با موفقیت انجام شد.")

    except Exception:
        conn.rollback()
        logger.exception("OTP verification failed")
        return error("خطای داخلی هنگام تأیید کد.", 500)
    finally:
        conn.close()


# =========================================================
# ACCOUNT / PROFILE
# =========================================================

@app.get("/api/v1/me")
@require_auth
def get_me():
    return response(public_user(g.user))


@app.patch("/api/v1/me")
@require_auth
def update_me():
    data = get_json()

    name = str(data.get("display_name", g.user["display_name"]))[:80]
    bio = str(data.get("bio", g.user["bio"]))[:300]

    username = data.get("username", g.user["username"])
    if username is not None:
        username = str(username).lower().strip()
        if username and not re.fullmatch(r"[a-z0-9_]{4,32}", username):
            return error("نام کاربری باید ۴ تا ۳۲ حرف انگلیسی، عدد یا زیرخط باشد.")

    try:
        user = db_query(
            """
            UPDATE users
            SET display_name = %s,
                bio = %s,
                username = %s,
                updated_at = NOW()
            WHERE id = %s
            RETURNING id, phone, display_name, username, bio, avatar_url
            """,
            (name, bio, username or None, g.user_id),
            fetchone=True,
            commit=True
        )
        return response(public_user(user), "پروفایل به‌روزرسانی شد.")
    except psycopg2.errors.UniqueViolation:
        return error("این نام کاربری قبلاً ثبت شده است.", 409)


@app.post("/api/v1/auth/logout")
@require_auth
def logout():
    header = request.headers.get("Authorization", "")
    token = header[7:].strip()

    db_query(
        """
        UPDATE sessions
        SET revoked_at = NOW()
        WHERE token_hash = %s AND revoked_at IS NULL
        """,
        (hash_token(token),),
        commit=True
    )
    return response({}, "از حساب خارج شدید.")


# =========================================================
# CONTACTS
# =========================================================

@app.get("/api/v1/contacts")
@require_auth
def list_contacts():
    rows = db_query(
        """
        SELECT u.id, u.phone, u.display_name, u.username,
               u.bio, u.avatar_url
        FROM contacts c
        JOIN users u ON u.id = c.contact_user_id
        WHERE c.owner_id = %s
        ORDER BY u.display_name ASC
        """,
        (g.user_id,),
        fetchall=True
    )
    return response([public_user(x) for x in rows])


@app.post("/api/v1/contacts")
@require_auth
def add_contact():
    data = get_json()
    phone = normalize_iran_phone(data.get("phone", ""))

    if not phone:
        return error("شماره موبایل معتبر نیست.")

    user = db_query(
        "SELECT id FROM users WHERE phone = %s AND is_active = TRUE",
        (phone,),
        fetchone=True
    )

    if not user:
        return error("این شماره هنوز در MASIH GRAM ثبت‌نام نکرده است.", 404)

    if user["id"] == g.user_id:
        return error("نمی‌توانید خودتان را به مخاطبین اضافه کنید.")

    db_query(
        """
        INSERT INTO contacts(owner_id, contact_user_id)
        VALUES(%s, %s)
        ON CONFLICT DO NOTHING
        """,
        (g.user_id, user["id"]),
        commit=True
    )
    return response({"user_id": user["id"]}, "مخاطب اضافه شد.")


# =========================================================
# CONVERSATIONS / PRIVATE CHAT / GROUP / CHANNEL
# =========================================================

@app.get("/api/v1/conversations")
@require_auth
def list_conversations():
    rows = db_query(
        """
        SELECT c.id, c.title, c.type, c.created_at, c.updated_at,
               (
                   SELECT m.body
                   FROM messages m
                   WHERE m.conversation_id = c.id
                     AND m.deleted_at IS NULL
                   ORDER BY m.id DESC
                   LIMIT 1
               ) AS last_message
        FROM conversations c
        JOIN conversation_members cm
          ON cm.conversation_id = c.id
        WHERE cm.user_id = %s
        ORDER BY c.updated_at DESC
        """,
        (g.user_id,),
        fetchall=True
    )

    return response([dict(x) for x in rows])


@app.post("/api/v1/conversations/private")
@require_auth
def create_private_conversation():
    data = get_json()
    other_id = data.get("user_id")

    try:
        other_id = int(other_id)
    except (TypeError, ValueError):
        return error("شناسه کاربر معتبر نیست.")

    if other_id == g.user_id:
        return error("گفت‌وگوی خصوصی با خودتان امکان‌پذیر نیست.")

    other = db_query(
        "SELECT id FROM users WHERE id = %s AND is_active = TRUE",
        (other_id,),
        fetchone=True
    )
    if not other:
        return error("کاربر پیدا نشد.", 404)

    existing = db_query(
        """
        SELECT c.id
        FROM conversations c
        JOIN conversation_members a ON a.conversation_id = c.id
        JOIN conversation_members b ON b.conversation_id = c.id
        WHERE c.type = 'private'
          AND a.user_id = %s
          AND b.user_id = %s
        LIMIT 1
        """,
        (g.user_id, other_id),
        fetchone=True
    )

    if existing:
        return response({"conversation_id": existing["id"]})

    conn = db_connect()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """
            INSERT INTO conversations(type, owner_id)
            VALUES('private', %s)
            RETURNING id
            """,
            (g.user_id,)
        )
        conversation = cur.fetchone()
        conversation_id = conversation["id"]

        cur.execute(
            """
            INSERT INTO conversation_members(conversation_id, user_id, role)
            VALUES(%s, %s, 'member'), (%s, %s, 'member')
            """,
            (conversation_id, g.user_id, conversation_id, other_id)
        )
        conn.commit()
        return response({"conversation_id": conversation_id},
                        "گفت‌وگوی خصوصی ساخته شد.", 201)
    except Exception:
        conn.rollback()
        logger.exception("Private conversation creation failed")
        return error("ساخت گفت‌وگو انجام نشد.", 500)
    finally:
        conn.close()


@app.post("/api/v1/conversations")
@require_auth
def create_group_or_channel():
    data = get_json()
    title = str(data.get("title", "")).strip()[:100]
    kind = str(data.get("type", "group")).lower()

    if not title:
        return error("نام گروه یا کانال را وارد کنید.")

    if kind not in ("group", "channel"):
        return error("نوع گفت‌وگو معتبر نیست.")

    conn = db_connect()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """
            INSERT INTO conversations(title, type, owner_id)
            VALUES(%s, %s, %s)
            RETURNING id, title, type
            """,
            (title, kind, g.user_id)
        )
        conversation = cur.fetchone()

        cur.execute(
            """
            INSERT INTO conversation_members(conversation_id, user_id, role)
            VALUES(%s, %s, 'owner')
            """,
            (conversation["id"], g.user_id)
        )
        conn.commit()
        return response(dict(conversation),
                        "ساخت با موفقیت انجام شد.", 201)
    except Exception:
        conn.rollback()
        logger.exception("Group/channel creation failed")
        return error("ساخت گروه یا کانال انجام نشد.", 500)
    finally:
        conn.close()


@app.post("/api/v1/conversations/<int:conversation_id>/members")
@require_auth
def add_conversation_member(conversation_id):
    data = get_json()
    try:
        member_id = int(data.get("user_id"))
    except (TypeError, ValueError):
        return error("شناسه عضو معتبر نیست.")

    role = db_query(
        """
        SELECT role FROM conversation_members
        WHERE conversation_id = %s AND user_id = %s
        """,
        (conversation_id, g.user_id),
        fetchone=True
    )
    if not role or role["role"] not in ("owner", "admin"):
        return error("اجازه افزودن عضو را ندارید.", 403)

    db_query(
        """
        INSERT INTO conversation_members(conversation_id, user_id, role)
        SELECT %s, id, 'member'
        FROM users
        WHERE id = %s AND is_active = TRUE
        ON CONFLICT DO NOTHING
        """,
        (conversation_id, member_id),
        commit=True
    )
    return response({"user_id": member_id}, "درخواست افزودن عضو ثبت شد.")


# =========================================================
# MESSAGES
# =========================================================

def is_member(conversation_id, user_id):
    row = db_query(
        """
        SELECT 1 FROM conversation_members
        WHERE conversation_id = %s AND user_id = %s
        """,
        (conversation_id, user_id),
        fetchone=True
    )
    return bool(row)


@app.get("/api/v1/conversations/<int:conversation_id>/messages")
@require_auth
def get_messages(conversation_id):
    if not is_member(conversation_id, g.user_id):
        return error("به این گفت‌وگو دسترسی ندارید.", 403)

    try:
        limit = int(request.args.get("limit", 50))
        before_id = int(request.args.get("before_id", 0))
    except ValueError:
        return error("پارامترهای صفحه‌بندی معتبر نیستند.")

    limit = max(1, min(limit, 100))

    rows = db_query(
        """
        SELECT m.id, m.conversation_id, m.sender_id,
               m.message_type, m.body, m.reply_to, m.created_at,
               u.display_name, u.username
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_id = %s
          AND m.deleted_at IS NULL
          AND (%s = 0 OR m.id < %s)
        ORDER BY m.id DESC
        LIMIT %s
        """,
        (conversation_id, before_id, before_id, limit),
        fetchall=True
    )

    return response([dict(x) for x in reversed(rows)])


@app.post("/api/v1/conversations/<int:conversation_id>/messages")
@require_auth
def send_message(conversation_id):
    if not is_member(conversation_id, g.user_id):
        return error("به این گفت‌وگو دسترسی ندارید.", 403)

    data = get_json()
    body = str(data.get("body", "")).strip()
    message_type = str(data.get("message_type", "text"))
    reply_to = data.get("reply_to")

    if not body:
        return error("متن پیام خالی است.")

    if len(body) > 10000:
        return error("طول پیام بیش از حد مجاز است.")

    if message_type not in ("text", "system"):
        return error("این نوع پیام هنوز از طریق این API پشتیبانی نمی‌شود.")

    try:
        row = db_query(
            """
            INSERT INTO messages(
                conversation_id, sender_id, message_type, body, reply_to
            )
            VALUES(%s, %s, %s, %s, %s)
            RETURNING id, conversation_id, sender_id,
                      message_type, body, reply_to, created_at
            """,
            (conversation_id, g.user_id, message_type, body, reply_to),
            fetchone=True,
            commit=True
        )

        db_query(
            """
            UPDATE conversations
            SET updated_at = NOW()
            WHERE id = %s
            """,
            (conversation_id,),
            commit=True
        )

        return response(dict(row), "پیام ذخیره شد.", 201)

    except Exception:
        logger.exception("Message creation failed")
        return error("ذخیره پیام انجام نشد.", 500)


@app.post("/api/v1/conversations/<int:conversation_id>/read")
@require_auth
def mark_conversation_read(conversation_id):
    if not is_member(conversation_id, g.user_id):
        return error("به این گفت‌وگو دسترسی ندارید.", 403)

    data = get_json()
    try:
        message_id = int(data.get("message_id"))
    except (TypeError, ValueError):
        return error("شناسه پیام معتبر نیست.")

    db_query(
        """
        UPDATE conversation_members
        SET last_read_message_id = GREATEST(
            COALESCE(last_read_message_id, 0), %s
        )
        WHERE conversation_id = %s AND user_id = %s
        """,
        (message_id, conversation_id, g.user_id),
        commit=True
    )

    db_query(
        """
        INSERT INTO message_receipts(message_id, user_id, delivered_at, read_at)
        SELECT id, %s, NOW(), NOW()
        FROM messages
        WHERE conversation_id = %s AND id <= %s
          AND sender_id <> %s
        ON CONFLICT(message_id, user_id)
        DO UPDATE SET read_at = NOW(), delivered_at =
            COALESCE(message_receipts.delivered_at, NOW())
        """,
        (g.user_id, conversation_id, message_id, g.user_id),
        commit=True
    )

    return response({}, "وضعیت خوانده‌شدن ثبت شد.")


# =========================================================
# STORIES
# =========================================================

@app.get("/api/v1/stories")
@require_auth
def list_stories():
    rows = db_query(
        """
        SELECT s.id, s.user_id, s.media_url, s.caption,
               s.created_at, s.expires_at,
               u.display_name, u.username
        FROM stories s
        JOIN users u ON u.id = s.user_id
        WHERE s.expires_at > NOW()
        ORDER BY s.created_at DESC
        LIMIT 200
        """,
        fetchall=True
    )
    return response([dict(x) for x in rows])


@app.post("/api/v1/stories")
@require_auth
def create_story():
    data = get_json()
    media_url = str(data.get("media_url", "")).strip()
    caption = str(data.get("caption", ""))[:500]

    if not media_url.startswith("https://"):
        return error("آدرس رسانه باید HTTPS باشد.")

    row = db_query(
        """
        INSERT INTO stories(user_id, media_url, caption, expires_at)
        VALUES(%s, %s, %s, NOW() + INTERVAL '24 hours')
        RETURNING id, user_id, media_url, caption, created_at, expires_at
        """,
        (g.user_id, media_url, caption),
        fetchone=True,
        commit=True
    )
    return response(dict(row), "استوری ثبت شد.", 201)


@app.post("/api/v1/stories/<int:story_id>/view")
@require_auth
def view_story(story_id):
    story = db_query(
        """
        SELECT id FROM stories
        WHERE id = %s AND expires_at > NOW()
        """,
        (story_id,),
        fetchone=True
    )
    if not story:
        return error("استوری پیدا نشد.", 404)

    db_query(
        """
        INSERT INTO story_views(story_id, viewer_id)
        VALUES(%s, %s)
        ON CONFLICT DO NOTHING
        """,
        (story_id, g.user_id),
        commit=True
    )
    return response({}, "بازدید ثبت شد.")


# =========================================================
# CALL REQUESTS
# This records call invitations only. Real audio/video needs
# WebRTC signaling and a TURN/STUN infrastructure.
# =========================================================

@app.post("/api/v1/calls")
@require_auth
def create_call():
    data = get_json()

    try:
        receiver_id = int(data.get("receiver_id"))
    except (TypeError, ValueError):
        return error("شناسه مخاطب معتبر نیست.")

    call_type = str(data.get("type", "audio")).lower()
    if call_type not in ("audio", "video"):
        return error("نوع تماس معتبر نیست.")

    receiver = db_query(
        "SELECT id FROM users WHERE id = %s AND is_active = TRUE",
        (receiver_id,),
        fetchone=True
    )
    if not receiver:
        return error("مخاطب پیدا نشد.", 404)

    row = db_query(
        """
        INSERT INTO call_sessions(caller_id, receiver_id, call_type)
        VALUES(%s, %s, %s)
        RETURNING id, caller_id, receiver_id, call_type, status, created_at
        """,
        (g.user_id, receiver_id, call_type),
        fetchone=True,
        commit=True
    )
    return response(dict(row), "درخواست تماس ثبت شد.", 201)


@app.patch("/api/v1/calls/<int:call_id>")
@require_auth
def update_call(call_id):
    data = get_json()
    status = str(data.get("status", "")).lower()

    if status not in ("accepted", "rejected", "ended", "missed"):
        return error("وضعیت تماس معتبر نیست.")

    row = db_query(
        """
        UPDATE call_sessions
        SET status = %s,
            ended_at = CASE
                WHEN %s IN ('rejected', 'ended', 'missed')
                THEN NOW() ELSE ended_at END
        WHERE id = %s
          AND (caller_id = %s OR receiver_id = %s)
        RETURNING id, status
        """,
        (status, status, call_id, g.user_id, g.user_id),
        fetchone=True,
        commit=True
    )

    if not row:
        return error("تماس پیدا نشد یا اجازه تغییر ندارید.", 404)

    return response(dict(row), "وضعیت تماس به‌روزرسانی شد.")


# =========================================================
# HEALTH / SYSTEM
# =========================================================

@app.get("/")
def index():
    return jsonify({
        "name": APP_NAME,
        "status": "online",
        "api_version": API_VERSION
    })


@app.get("/health")
def health():
    database_ok = False

    try:
        db_query("SELECT 1", fetchone=True)
        database_ok = True
    except Exception:
        logger.exception("Database health check failed")

    return jsonify({
        "name": APP_NAME,
        "status": "ok" if database_ok else "degraded",
        "database": database_ok,
        "sms_configured": bool(
            KAVENEGAR_API_KEY and KAVENEGAR_TEMPLATE and OTP_SECRET
        ),
        "time": now_utc().isoformat()
    }), 200 if database_ok else 503


@app.errorhandler(404)
def not_found(_):
    return error("مسیر مورد نظر پیدا نشد.", 404)


@app.errorhandler(405)
def method_not_allowed(_):
    return error("روش درخواست پشتیبانی نمی‌شود.", 405)


@app.errorhandler(413)
def too_large(_):
    return error("حجم درخواست بیش از حد مجاز است.", 413)


@app.errorhandler(500)
def internal_error(_):
    logger.exception("Unhandled server error")
    return error("خطای داخلی سرور.", 500)


# =========================================================
# STARTUP
# =========================================================

if __name__ == "__main__":
    if DATABASE_URL:
        init_database()

    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
