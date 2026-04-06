import streamlit as st
import sqlite3
import bcrypt
import jwt
import imaplib
import email
from email.header import decode_header
from datetime import datetime, timedelta

# -----------------------------
# Config
# -----------------------------
SECRET_KEY = "your_super_secret_key"

st.set_page_config(page_title="User Auth + Inbox", page_icon="📥", layout="centered")

# Hide Streamlit menu
st.markdown("""
    <style>
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# -----------------------------
# Database setup
# -----------------------------
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT NOT NULL
)
""")
conn.commit()

# -----------------------------
# Helper functions
# -----------------------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def create_user(full_name, email, password):
    try:
        hashed_password = hash_password(password)
        c.execute(
            "INSERT INTO users (full_name, email, password, created_at) VALUES (?, ?, ?, ?)",
            (full_name, email, hashed_password, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def generate_token(user_id, email_id):
    payload = {
        "user_id": user_id,
        "email": email_id,
        "exp": datetime.utcnow() + timedelta(hours=2),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def login_user(email_id, password):
    c.execute("SELECT * FROM users WHERE email=?", (email_id,))
    user = c.fetchone()
    if user and verify_password(password, user[3]):
        return user
    return None


def fetch_inbox_emails(user_email, app_password, limit=20):
    emails = []
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(user_email, app_password)
    mail.select("inbox")

    _, message_numbers = mail.search(None, "ALL")
    message_ids = message_numbers[0].split()
    latest_ids = message_ids[-limit:]

    for msg_id in reversed(latest_ids):
        _, msg_data = mail.fetch(msg_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg.get("Subject", "No Subject"))[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding or "utf-8", errors="ignore")

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode(errors="ignore")
                            break
                else:
                    body = msg.get_payload(decode=True).decode(errors="ignore")

                emails.append({
                    "from": msg.get("From", "Unknown"),
                    "subject": subject,
                    "date": msg.get("Date", "Unknown"),
                    "body": body[:5000]
                })

    mail.logout()
    return emails


# -----------------------------
# Session state
# -----------------------------
if "page" not in st.session_state:
    st.session_state.page = "login"

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_name = ""
    st.session_state.token = None

# -----------------------------
# Auth header
# -----------------------------
if not (st.session_state.logged_in and st.session_state.page == "dashboard"):
    st.title("🔐 User Registration & Login")
    st.caption("Built with Streamlit + SQLite + bcrypt + JWT + IMAP")

# -----------------------------
# Registration
# -----------------------------
if st.session_state.page == "register":
    st.subheader("Create New Account")
    full_name = st.text_input("Full Name")
    email_id = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if not full_name or not email_id or not password:
            st.warning("Please fill all fields")
        elif password != confirm_password:
            st.error("Passwords do not match")
        else:
            if create_user(full_name, email_id, password):
                st.success("Registration successful! Please login.")
                st.session_state.page = "login"
                st.rerun()
            else:
                st.error("Email already exists")

    if st.button("⬅ Back to Login"):
        st.session_state.page = "login"
        st.rerun()

# -----------------------------
# Login
# -----------------------------
if st.session_state.page == "login":
    st.subheader("Login to Your Account")
    email_id = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = login_user(email_id, password)
        if user:
            st.session_state.logged_in = True
            st.session_state.user_name = user[1]
            st.session_state.token = generate_token(user[0], user[2])
            st.session_state.page = "dashboard"
            st.rerun()
        else:
            st.error("Invalid email or password")

    st.markdown("---")
    st.write("New user?")
    if st.button("Register here"):
        st.session_state.page = "register"
        st.rerun()

# -----------------------------
# Dashboard + Inbox
# -----------------------------
if st.session_state.logged_in and st.session_state.page == "dashboard":
    st.markdown(f"""
    <div style='padding:18px;border-radius:16px;border:1px solid #e5e7eb;margin-bottom:16px;'>
        <h2 style='margin:0;'>👋 Welcome, {st.session_state.user_name}</h2>
        <p style='margin:6px 0 0 0;color:gray;'>Your secure email dashboard</p>
    </div>
    """, unsafe_allow_html=True)

    top1, top2 = st.columns([4,1])
    with top2:
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user_name = ""
            st.session_state.token = None
            st.session_state.page = "login"
            st.rerun()

    gmail_email = st.text_input("📧 Gmail Address", placeholder="you@gmail.com")
    gmail_app_password = st.text_input("🔑 App Password", type="password")

    if st.button("📨 Load Inbox", use_container_width=True):
        try:
            st.session_state.inbox_emails = fetch_inbox_emails(gmail_email, gmail_app_password, limit=20)
            st.session_state.selected_email = 0
        except Exception as e:
            st.error(f"Failed to load inbox: {e}")

    if "inbox_emails" in st.session_state and st.session_state.inbox_emails:
        left, right = st.columns([1, 2])

        with left:
            st.subheader("📬 Inbox")
            for i, mail_item in enumerate(st.session_state.inbox_emails):
                label = f"{i+1}. {mail_item['subject'][:40]}"
                if st.button(label, key=f"mail_{i}", use_container_width=True):
                    st.session_state.selected_email = i
                    st.rerun()

        with right:
            selected = st.session_state.inbox_emails[st.session_state.get("selected_email", 0)]
            st.subheader(f"📩 {selected['subject']}")
            st.write(f"**From:** {selected['from']}")
            st.write(f"**Date:** {selected['date']}")
            st.markdown("---")
            st.write(selected['body'])