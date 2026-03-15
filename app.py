"""
app.py — VaultAI: AI-Powered Password Manager
Main Streamlit application entry point.

Pages:
  🔐 Login / Register
  🗄️ Vault
  ➕ Add / Edit Credential
  🔑 Password Generator
  🤖 AI Advisor
  📊 Security Dashboard
  📋 Audit Log
"""

import streamlit as st
import pyperclip
import time
import threading
from datetime import datetime

import database as db
import auth
from encryption import encrypt, decrypt
from password_generator import generate_password, generate_passphrase, password_suggestions
from ai_advisor import (
    analyze_password, get_security_tips, analyze_vault_security,
    chat_with_advisor, explain_breach_risk,
)
from breach_checker import check_password_breach
from utils.helpers import (
    password_strength, find_reused_passwords, compute_security_score, sanitize_text
)
from config import APP_TITLE, APP_ICON, CLIPBOARD_CLEAR_SECONDS

# ─── Page Config ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title=APP_TITLE,
    page_icon=APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── DB Init ──────────────────────────────────────────────────────────────────
db.init_db()

# ─── Custom CSS ───────────────────────────────────────────────────────────────

def inject_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;800&display=swap');

    :root {
        --bg:        #0a0c10;
        --surface:   #111318;
        --surface2:  #1a1d24;
        --border:    #2a2d36;
        --accent:    #00d4aa;
        --accent2:   #7c3aed;
        --danger:    #ef4444;
        --warn:      #f59e0b;
        --success:   #22c55e;
        --text:      #e2e8f0;
        --muted:     #64748b;
        --mono:      'JetBrains Mono', monospace;
        --sans:      'Syne', sans-serif;
    }

    .stApp { background: var(--bg); color: var(--text); font-family: var(--sans); }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: var(--surface) !important;
        border-right: 1px solid var(--border);
    }
    [data-testid="stSidebar"] * { color: var(--text) !important; }

    /* Cards */
    .vault-card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 16px 20px;
        margin-bottom: 10px;
        transition: border-color 0.2s;
    }
    .vault-card:hover { border-color: var(--accent); }

    /* Metric boxes */
    .metric-box {
        background: var(--surface2);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .metric-box .val {
        font-size: 2.4rem;
        font-weight: 800;
        font-family: var(--mono);
        color: var(--accent);
    }
    .metric-box .lbl { color: var(--muted); font-size: 0.8rem; margin-top: 4px; }

    /* Strength bar */
    .strength-bar-wrap { background: var(--border); border-radius: 4px; height: 8px; }
    .strength-bar { height: 8px; border-radius: 4px; transition: width 0.4s; }

    /* Badge */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.72rem;
        font-weight: 600;
        font-family: var(--mono);
    }
    .badge-danger  { background: #ef444420; color: var(--danger);  border: 1px solid #ef444440; }
    .badge-warn    { background: #f59e0b20; color: var(--warn);   border: 1px solid #f59e0b40; }
    .badge-success { background: #22c55e20; color: var(--success); border: 1px solid #22c55e40; }
    .badge-accent  { background: #00d4aa20; color: var(--accent);  border: 1px solid #00d4aa40; }

    /* Password field */
    .pwd-display {
        font-family: var(--mono);
        background: var(--surface2);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 12px 16px;
        font-size: 0.95rem;
        letter-spacing: 0.04em;
        word-break: break-all;
    }

    /* Page title */
    .page-title {
        font-size: 1.8rem;
        font-weight: 800;
        margin-bottom: 0.2rem;
        background: linear-gradient(90deg, var(--accent), var(--accent2));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    /* Input fields */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div {
        background: var(--surface2) !important;
        border: 1px solid var(--border) !important;
        color: var(--text) !important;
        border-radius: 8px !important;
    }

    /* Buttons */
    .stButton > button {
        background: var(--surface2);
        border: 1px solid var(--border);
        color: var(--text);
        border-radius: 8px;
        font-family: var(--sans);
        font-weight: 600;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        border-color: var(--accent);
        color: var(--accent);
    }

    /* Primary button via class */
    .btn-primary > button {
        background: var(--accent) !important;
        color: #0a0c10 !important;
        border: none !important;
    }
    .btn-primary > button:hover {
        background: #00b894 !important;
        color: #0a0c10 !important;
    }

    /* AI response box */
    .ai-response {
        background: var(--surface2);
        border-left: 3px solid var(--accent2);
        border-radius: 0 8px 8px 0;
        padding: 16px 20px;
        font-size: 0.9rem;
        line-height: 1.7;
    }

    /* Hide Streamlit branding */
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding-top: 1.5rem; }
    </style>
    """, unsafe_allow_html=True)


inject_css()


# ─── Sidebar Navigation ───────────────────────────────────────────────────────

def render_sidebar():
    with st.sidebar:
        st.markdown(f"## {APP_ICON} **VaultAI**")
        st.markdown("*AI-Powered Password Manager*")
        st.divider()

        if auth.is_authenticated():
            st.markdown(f"👤 **{auth.get_username()}**")
            st.caption(f"Session active")
            st.divider()

            pages = {
                "🗄️ Vault":              "vault",
                "➕ Add Credential":    "add",
                "🔑 Password Generator": "generator",
                "🤖 AI Advisor":         "advisor",
                "📊 Security Dashboard": "dashboard",
                "📋 Audit Log":          "audit",
            }
            for label, page_key in pages.items():
                if st.button(label, use_container_width=True, key=f"nav_{page_key}"):
                    st.session_state.current_page = page_key
                    st.rerun()

            st.divider()
            if st.button("🚪 Logout", use_container_width=True):
                auth.logout_user()
                st.rerun()
        else:
            st.info("Please log in to access your vault.")


# ─── Auth Pages ───────────────────────────────────────────────────────────────

def page_auth():
    col_l, col_m, col_r = st.columns([1, 2, 1])
    with col_m:
        st.markdown('<div class="page-title">🔐 VaultAI</div>', unsafe_allow_html=True)
        st.markdown("*Enterprise-grade AI Password Manager*")
        st.markdown("---")

        tab_login, tab_register = st.tabs(["🔑 Login", "📝 Register"])

        with tab_login:
            st.markdown("#### Sign in to your vault")
            username = st.text_input("Username", key="login_user", placeholder="your_username")
            password = st.text_input("Master Password", type="password", key="login_pwd",
                                      placeholder="Enter your master password")
            if st.button("🔓 Unlock Vault", use_container_width=True, key="btn_login"):
                if username and password:
                    with st.spinner("Verifying credentials..."):
                        ok, err = auth.login_user(username, password)
                    if ok:
                        st.success("✅ Access granted!")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error(f"❌ {err}")
                else:
                    st.warning("Please fill in all fields.")

        with tab_register:
            st.markdown("#### Create a new vault")
            st.warning("⚠️ Your master password cannot be recovered. Store it safely.")
            new_user = st.text_input("Choose Username", key="reg_user")
            new_pwd = st.text_input("Create Master Password", type="password", key="reg_pwd")
            confirm_pwd = st.text_input("Confirm Master Password", type="password", key="reg_confirm")

            if new_pwd:
                info = password_strength(new_pwd)
                st.markdown(f"""
                <div class="strength-bar-wrap">
                  <div class="strength-bar" style="width:{info['score']}%; background:{info['color']}"></div>
                </div>
                <small>Strength: <strong style="color:{info['color']}">{info['label']}</strong> &nbsp; ({info['score']}/100)</small>
                """, unsafe_allow_html=True)

            if st.button("🛡️ Create Vault", use_container_width=True, key="btn_register"):
                if not new_user or not new_pwd:
                    st.warning("Please fill in all fields.")
                elif new_pwd != confirm_pwd:
                    st.error("❌ Passwords do not match.")
                elif len(new_pwd) < 8:
                    st.error("❌ Master password must be at least 8 characters.")
                else:
                    ok, err = auth.register_user(new_user, new_pwd)
                    if ok:
                        st.success("✅ Vault created! Please log in.")
                    else:
                        st.error(f"❌ {err}")


# ─── Vault Page ───────────────────────────────────────────────────────────────

def page_vault():
    st.markdown('<div class="page-title">🗄️ Password Vault</div>', unsafe_allow_html=True)
    st.markdown("Your encrypted credential store")
    st.divider()

    aes_key = auth.get_aes_key()
    user_id = auth.get_user_id()

    col_search, col_add = st.columns([3, 1])
    with col_search:
        search = st.text_input("🔍 Search credentials", placeholder="Search by website or username...")
    with col_add:
        if st.button("➕ Add New", use_container_width=True):
            st.session_state.current_page = "add"
            st.session_state.edit_cred_id = None
            st.rerun()

    credentials = db.get_credentials(user_id, search)

    if not credentials:
        st.info("🔒 Your vault is empty. Add your first credential above.")
        return

    st.caption(f"Showing {len(credentials)} credential(s)")

    # Reuse detection
    decrypted_for_reuse = []
    for cred in credentials:
        try:
            pwd = decrypt(cred["password_enc"], aes_key)
            decrypted_for_reuse.append({"website": cred["website"], "password": pwd, "id": cred["id"]})
        except Exception:
            pass

    reused_map = find_reused_passwords(decrypted_for_reuse)
    reused_websites = {site for sites in reused_map.values() for site in sites}

    for cred in credentials:
        with st.container():
            try:
                decrypted_pwd = decrypt(cred["password_enc"], aes_key)
                strength_info = password_strength(decrypted_pwd)
                is_reused = cred["website"] in reused_websites
                is_weak = strength_info["score"] < 50

                badge_html = ""
                if is_weak:
                    badge_html += '<span class="badge badge-danger">Weak</span> '
                if is_reused:
                    badge_html += '<span class="badge badge-warn">Reused</span> '
                if not is_weak and not is_reused:
                    badge_html += '<span class="badge badge-success">Secure</span>'

                st.markdown(f"""
                <div class="vault-card">
                  <div style="display:flex; justify-content:space-between; align-items:flex-start">
                    <div>
                      <strong style="font-size:1.05rem">{cred['website']}</strong>
                      &nbsp; {badge_html}
                      <div style="color:var(--muted); font-size:0.85rem; margin-top:4px">
                        👤 {cred['username']}
                        &nbsp;·&nbsp; 🏷️ {cred.get('category','General')}
                        &nbsp;·&nbsp; 🕒 {cred['updated_at'][:10]}
                      </div>
                    </div>
                    <div style="text-align:right">
                      <div class="strength-bar-wrap" style="width:80px; display:inline-block">
                        <div class="strength-bar" style="width:{strength_info['score']}%; background:{strength_info['color']}"></div>
                      </div>
                      <div style="font-size:0.7rem; color:var(--muted)">{strength_info['label']}</div>
                    </div>
                  </div>
                </div>
                """, unsafe_allow_html=True)

                c1, c2, c3, c4, c5 = st.columns([2, 2, 1, 1, 1])
                with c1:
                    show_key = f"show_{cred['id']}"
                    if st.session_state.get(show_key):
                        st.code(decrypted_pwd, language=None)
                        if st.button("🙈 Hide", key=f"hide_{cred['id']}", use_container_width=True):
                            st.session_state[show_key] = False
                            st.rerun()
                    else:
                        if st.button("👁 Reveal", key=f"reveal_{cred['id']}", use_container_width=True):
                            st.session_state[show_key] = True
                            st.rerun()
                with c2:
                    if st.button("📋 Copy", key=f"copy_{cred['id']}", use_container_width=True):
                        try:
                            pyperclip.copy(decrypted_pwd)
                            st.toast(f"✅ Copied! Clears in {CLIPBOARD_CLEAR_SECONDS}s")
                            # Clear clipboard after delay in background thread
                            def clear_cb():
                                time.sleep(CLIPBOARD_CLEAR_SECONDS)
                                pyperclip.copy("")
                            threading.Thread(target=clear_cb, daemon=True).start()
                        except Exception:
                            st.toast("Copy not available in this environment.")
                with c3:
                    if st.button("🤖", key=f"ai_{cred['id']}", use_container_width=True, help="AI Analysis"):
                        st.session_state[f"ai_result_{cred['id']}"] = analyze_password(decrypted_pwd, cred["website"])
                with c4:
                    if st.button("✏️", key=f"edit_{cred['id']}", use_container_width=True, help="Edit"):
                        st.session_state.edit_cred_id = cred["id"]
                        st.session_state.current_page = "add"
                        st.rerun()
                with c5:
                    if st.button("🗑️", key=f"del_{cred['id']}", use_container_width=True, help="Delete"):
                        st.session_state[f"confirm_del_{cred['id']}"] = True
                        st.rerun()

                # Delete confirmation
                if st.session_state.get(f"confirm_del_{cred['id']}"):
                    st.warning(f"Delete **{cred['website']}**? This cannot be undone.")
                    col_y, col_n = st.columns(2)
                    with col_y:
                        if st.button("✅ Yes, Delete", key=f"yes_del_{cred['id']}"):
                            db.delete_credential(cred["id"], user_id)
                            st.success("Deleted.")
                            st.session_state[f"confirm_del_{cred['id']}"] = False
                            st.rerun()
                    with col_n:
                        if st.button("❌ Cancel", key=f"no_del_{cred['id']}"):
                            st.session_state[f"confirm_del_{cred['id']}"] = False
                            st.rerun()

                # AI result display
                if st.session_state.get(f"ai_result_{cred['id']}"):
                    with st.expander("🤖 AI Security Analysis", expanded=True):
                        st.markdown(
                            f'<div class="ai-response">{st.session_state[f"ai_result_{cred[id]}"]}</div>',
                            unsafe_allow_html=True
                        )
                        st.markdown(st.session_state[f"ai_result_{cred['id']}"])
                        if st.button("✕ Dismiss", key=f"dismiss_ai_{cred['id']}"):
                            st.session_state[f"ai_result_{cred['id']}"] = None

            except Exception as e:
                st.error(f"Could not decrypt credential #{cred['id']}: {e}")

        st.markdown("---")


# ─── Add / Edit Credential ────────────────────────────────────────────────────

def page_add_credential():
    edit_id = st.session_state.get("edit_cred_id")
    is_edit = edit_id is not None
    aes_key = auth.get_aes_key()
    user_id = auth.get_user_id()

    title = "✏️ Edit Credential" if is_edit else "➕ Add Credential"
    st.markdown(f'<div class="page-title">{title}</div>', unsafe_allow_html=True)
    st.divider()

    # Pre-fill for edit
    prefill = {"website": "", "username": "", "password": "", "notes": "", "category": "General"}
    if is_edit:
        existing = db.get_credential_by_id(edit_id, user_id)
        if existing:
            try:
                prefill["website"]  = existing["website"]
                prefill["username"] = existing["username"]
                prefill["password"] = decrypt(existing["password_enc"], aes_key)
                prefill["notes"]    = decrypt(existing["notes_enc"], aes_key) if existing.get("notes_enc") else ""
                prefill["category"] = existing.get("category", "General")
            except Exception as e:
                st.error(f"Could not load credential: {e}")

    col_form, col_tools = st.columns([3, 2])

    with col_form:
        website  = st.text_input("🌐 Website / Service", value=prefill["website"],
                                  placeholder="https://github.com")
        username = st.text_input("👤 Username / Email", value=prefill["username"],
                                  placeholder="user@example.com")

        # Password field with strength meter
        password_val = st.text_input("🔑 Password", value=prefill["password"],
                                      type="password", key="add_pwd_field")
        if password_val:
            info = password_strength(password_val)
            st.markdown(f"""
            <div class="strength-bar-wrap">
              <div class="strength-bar" style="width:{info['score']}%; background:{info['color']}"></div>
            </div>
            <small>
              Strength: <strong style="color:{info['color']}">{info['label']}</strong>
              &nbsp;·&nbsp; Score: {info['score']}/100
              &nbsp;·&nbsp; Entropy: {info['entropy']} bits
            </small>
            """, unsafe_allow_html=True)

        category = st.selectbox("🏷️ Category",
                                 ["General", "Work", "Banking", "Social", "Shopping", "Email", "Other"],
                                 index=["General", "Work", "Banking", "Social", "Shopping", "Email", "Other"].index(prefill["category"]))
        notes = st.text_area("📝 Notes (optional)", value=prefill["notes"],
                              placeholder="2FA backup codes, security questions...", height=80)

        col_save, col_cancel = st.columns(2)
        with col_save:
            btn_label = "💾 Update" if is_edit else "🔒 Save Encrypted"
            if st.button(btn_label, use_container_width=True, key="btn_save_cred"):
                if not website or not username or not password_val:
                    st.error("❌ Website, username, and password are required.")
                else:
                    try:
                        enc_pwd   = encrypt(sanitize_text(password_val), aes_key)
                        enc_notes = encrypt(sanitize_text(notes), aes_key) if notes else ""
                        if is_edit:
                            db.update_credential(edit_id, user_id,
                                                  sanitize_text(website), sanitize_text(username),
                                                  enc_pwd, enc_notes, category)
                            st.success("✅ Credential updated.")
                        else:
                            db.add_credential(user_id, sanitize_text(website),
                                               sanitize_text(username), enc_pwd, enc_notes, category)
                            st.success("✅ Credential saved (AES-256 encrypted).")
                        time.sleep(0.8)
                        st.session_state.edit_cred_id = None
                        st.session_state.current_page = "vault"
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Save failed: {e}")
        with col_cancel:
            if st.button("❌ Cancel", use_container_width=True):
                st.session_state.edit_cred_id = None
                st.session_state.current_page = "vault"
                st.rerun()

    with col_tools:
        st.markdown("#### 🔑 Quick Password Generator")
        gen_len = st.slider("Length", 8, 64, 20, key="add_gen_len")
        g_upper = st.checkbox("Uppercase A-Z", value=True, key="add_g_upper")
        g_lower = st.checkbox("Lowercase a-z", value=True, key="add_g_lower")
        g_digit = st.checkbox("Digits 0-9",    value=True, key="add_g_digit")
        g_spec  = st.checkbox("Special chars",  value=True, key="add_g_spec")

        if st.button("⚡ Generate Password", use_container_width=True, key="add_gen"):
            try:
                gen_pwd = generate_password(gen_len, g_upper, g_lower, g_digit, g_spec)
                st.session_state.generated_for_form = gen_pwd
            except ValueError as e:
                st.error(str(e))

        if "generated_for_form" in st.session_state and st.session_state.generated_for_form:
            st.markdown("**Generated Password:**")
            st.code(st.session_state.generated_for_form, language=None)
            st.caption("👆 Copy this and paste it into the password field above.")

        # Breach check
        if password_val:
            st.markdown("---")
            st.markdown("#### 🔍 Breach Check")
            if st.button("Check HaveIBeenPwned", use_container_width=True, key="hibp_add"):
                with st.spinner("Checking breach databases..."):
                    count, msg = check_password_breach(password_val)
                if count > 0:
                    st.error(msg)
                elif count == 0:
                    st.success(msg)
                else:
                    st.warning(msg)


# ─── Password Generator Page ──────────────────────────────────────────────────

def page_generator():
    st.markdown('<div class="page-title">🔑 Password Generator</div>', unsafe_allow_html=True)
    st.markdown("Cryptographically secure password generation")
    st.divider()

    tab_random, tab_passphrase, tab_bulk = st.tabs(["Random Password", "Passphrase", "Bulk Generate"])

    with tab_random:
        col_opts, col_result = st.columns([1, 1])
        with col_opts:
            length   = st.slider("Password Length", 8, 128, 20)
            upper    = st.checkbox("Uppercase (A-Z)",       value=True)
            lower    = st.checkbox("Lowercase (a-z)",       value=True)
            digits   = st.checkbox("Digits (0-9)",          value=True)
            special  = st.checkbox("Special Characters",    value=True)
            no_ambig = st.checkbox("Exclude Ambiguous (0,O,1,l,I)", value=False)

            if st.button("⚡ Generate", use_container_width=True, key="gen_btn"):
                try:
                    pwd = generate_password(length, upper, lower, digits, special, no_ambig)
                    st.session_state.gen_result = pwd
                except ValueError as e:
                    st.error(str(e))

        with col_result:
            if st.session_state.get("gen_result"):
                pwd = st.session_state.gen_result
                info = password_strength(pwd)
                st.markdown("**Your Generated Password:**")
                st.markdown(f'<div class="pwd-display">{pwd}</div>', unsafe_allow_html=True)
                st.markdown(f"""
                <br>
                <div class="strength-bar-wrap">
                  <div class="strength-bar" style="width:{info['score']}%; background:{info['color']}"></div>
                </div>
                <small>
                  <strong style="color:{info['color']}">{info['label']}</strong>
                  &nbsp;·&nbsp; {info['score']}/100
                  &nbsp;·&nbsp; {info['entropy']} bits entropy
                </small>
                """, unsafe_allow_html=True)

                col_copy, col_new = st.columns(2)
                with col_copy:
                    if st.button("📋 Copy to Clipboard", use_container_width=True):
                        try:
                            pyperclip.copy(pwd)
                            st.toast(f"Copied! Clears in {CLIPBOARD_CLEAR_SECONDS}s")
                            threading.Thread(target=lambda: (time.sleep(CLIPBOARD_CLEAR_SECONDS), pyperclip.copy("")), daemon=True).start()
                        except Exception:
                            st.toast("Copy unavailable in this environment.")
                with col_new:
                    if st.button("🔄 Regenerate", use_container_width=True):
                        try:
                            st.session_state.gen_result = generate_password(length, upper, lower, digits, special, no_ambig)
                            st.rerun()
                        except ValueError as e:
                            st.error(str(e))

                # Check breach
                if st.button("🔍 Check Breaches", use_container_width=True):
                    with st.spinner("Querying HaveIBeenPwned..."):
                        count, msg = check_password_breach(pwd)
                    if count > 0:
                        st.error(msg)
                    elif count == 0:
                        st.success(msg)
                    else:
                        st.warning(msg)

                # AI Analysis
                if st.button("🤖 AI Analysis", use_container_width=True):
                    with st.spinner("CipherAI analyzing..."):
                        result = analyze_password(pwd)
                    st.markdown(f'<div class="ai-response">{result}</div>', unsafe_allow_html=True)
                    st.markdown(result)

    with tab_passphrase:
        word_count = st.slider("Word Count", 3, 8, 4)
        separator  = st.selectbox("Separator", ["-", "_", ".", " ", "!"])
        if st.button("⚡ Generate Passphrase", use_container_width=True):
            phrase = generate_passphrase(word_count, separator)
            st.session_state.gen_phrase = phrase

        if st.session_state.get("gen_phrase"):
            st.markdown(f'<div class="pwd-display">{st.session_state.gen_phrase}</div>', unsafe_allow_html=True)
            info = password_strength(st.session_state.gen_phrase)
            st.caption(f"Strength: **{info['label']}** · {info['score']}/100 · {info['entropy']} bits entropy")

    with tab_bulk:
        count = st.slider("Number of passwords to generate", 1, 20, 5)
        bl = st.slider("Length", 8, 64, 20, key="bulk_len")
        if st.button("⚡ Generate Batch", use_container_width=True):
            passwords = [generate_password(bl) for _ in range(count)]
            st.markdown("**Generated Passwords:**")
            for i, p in enumerate(passwords, 1):
                info = password_strength(p)
                col_n, col_pwd, col_str = st.columns([1, 5, 2])
                with col_n:    st.markdown(f"**{i}.**")
                with col_pwd:  st.code(p, language=None)
                with col_str:  st.markdown(f'<span class="badge" style="color:{info["color"]}">{info["label"]}</span>', unsafe_allow_html=True)


# ─── AI Advisor Page ─────────────────────────────────────────────────────────

def page_ai_advisor():
    st.markdown('<div class="page-title">🤖 AI Security Advisor</div>', unsafe_allow_html=True)
    st.markdown("Powered by **Qwen-3-32B** via Groq · Real-time cybersecurity intelligence")
    st.divider()

    tab_analyze, tab_tips, tab_chat, tab_vault_ai = st.tabs(
        ["Password Analysis", "Security Tips", "Ask CipherAI", "Vault Analysis"]
    )

    with tab_analyze:
        st.markdown("#### Analyze a Password")
        test_pwd  = st.text_input("Enter password to analyze (not stored)", type="password", key="ai_test_pwd")
        context   = st.text_input("Context (optional, e.g., website name)", key="ai_context")

        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("🤖 Analyze with AI", use_container_width=True, key="btn_ai_analyze"):
                if test_pwd:
                    with st.spinner("CipherAI analyzing..."):
                        result = analyze_password(test_pwd, context)
                    st.markdown("#### AI Analysis")
                    st.markdown(result)
                else:
                    st.warning("Please enter a password.")
        with col_b:
            if test_pwd:
                info = password_strength(test_pwd)
                st.markdown(f"""
                **Quick Score:**
                <div class="strength-bar-wrap">
                  <div class="strength-bar" style="width:{info['score']}%; background:{info['color']}"></div>
                </div>
                <small style="color:{info['color']}"><strong>{info['label']}</strong> — {info['score']}/100</small>
                """, unsafe_allow_html=True)

                # Breach check inline
                if st.button("🔍 Check Breaches", use_container_width=True, key="ai_breach"):
                    with st.spinner("Checking..."):
                        count, msg = check_password_breach(test_pwd)
                    if count > 0:
                        st.error(msg)
                        with st.spinner("Getting AI breach explanation..."):
                            exp = explain_breach_risk(count, context)
                        st.markdown(exp)
                    elif count == 0:
                        st.success(msg)
                    else:
                        st.warning(msg)

    with tab_tips:
        topic = st.selectbox("Select Topic", {
            "general": "General Password Security",
            "phishing": "Phishing Defense",
            "mfa": "Multi-Factor Authentication",
            "breach": "Responding to Breaches",
            "vault": "Enterprise Vault Management",
        })
        if st.button("💡 Get Expert Tips", use_container_width=True):
            with st.spinner("Consulting CipherAI..."):
                tips = get_security_tips(topic)
            st.markdown(tips)

    with tab_chat:
        st.markdown("#### Chat with CipherAI")
        if "chat_history" not in st.session_state:
            st.session_state.chat_history = []

        # Display history
        for msg in st.session_state.chat_history:
            role_icon = "👤" if msg["role"] == "user" else "🤖"
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        user_input = st.chat_input("Ask a cybersecurity question...")
        if user_input:
            st.session_state.chat_history.append({"role": "user", "content": user_input})
            with st.chat_message("user"):
                st.markdown(user_input)
            with st.chat_message("assistant"):
                with st.spinner("CipherAI thinking..."):
                    response = chat_with_advisor(user_input, st.session_state.chat_history[:-1])
                st.markdown(response)
            st.session_state.chat_history.append({"role": "assistant", "content": response})

        if st.session_state.chat_history:
            if st.button("🗑️ Clear Conversation"):
                st.session_state.chat_history = []
                st.rerun()

    with tab_vault_ai:
        st.markdown("#### Vault-Wide Security Analysis")
        st.markdown("AI analyses your entire vault and provides a prioritised remediation plan.")

        aes_key = auth.get_aes_key()
        user_id = auth.get_user_id()
        creds   = db.get_credentials(user_id)

        if not creds:
            st.info("Your vault is empty. Add credentials first.")
        else:
            decrypted = []
            for c in creds:
                try:
                    decrypted.append({"website": c["website"], "password": decrypt(c["password_enc"], aes_key)})
                except Exception:
                    pass

            overview = compute_security_score(decrypted)

            col1, col2, col3, col4 = st.columns(4)
            for col, (val, lbl) in zip(
                [col1, col2, col3, col4],
                [
                    (overview["breakdown"]["total"], "Total Credentials"),
                    (overview["breakdown"]["weak"],  "Weak Passwords"),
                    (overview["breakdown"]["reused"], "Reused Passwords"),
                    (f"{overview['score']}/100",     "Security Score"),
                ],
            ):
                with col:
                    st.markdown(f'<div class="metric-box"><div class="val">{val}</div><div class="lbl">{lbl}</div></div>', unsafe_allow_html=True)

            st.markdown("")
            if st.button("🤖 Get AI Recommendations", use_container_width=True):
                with st.spinner("CipherAI performing vault analysis..."):
                    ai_rec = analyze_vault_security(overview["breakdown"] | {"score": overview["score"], "grade": overview["grade"]})
                st.markdown(ai_rec)


# ─── Security Dashboard ───────────────────────────────────────────────────────

def page_dashboard():
    st.markdown('<div class="page-title">📊 Security Dashboard</div>', unsafe_allow_html=True)
    st.markdown("Real-time overview of your vault security posture")
    st.divider()

    aes_key = auth.get_aes_key()
    user_id = auth.get_user_id()
    creds   = db.get_credentials(user_id)

    decrypted = []
    for c in creds:
        try:
            pwd = decrypt(c["password_enc"], aes_key)
            decrypted.append({"website": c["website"], "password": pwd, "category": c.get("category","General")})
        except Exception:
            pass

    score_data  = compute_security_score(decrypted)
    reused_map  = find_reused_passwords(decrypted)
    weak_creds  = [d for d in decrypted if password_strength(d["password"])["score"] < 50]
    total       = len(creds)

    # ── Top metrics row ──
    c1, c2, c3, c4, c5 = st.columns(5)
    metric_data = [
        (total,                                   "Total Credentials"),
        (len(weak_creds),                         "Weak Passwords"),
        (sum(len(v) for v in reused_map.values()),"Reused Passwords"),
        (f"{score_data['score']}/100",            "Security Score"),
        (score_data["grade"],                     "Security Grade"),
    ]
    for col, (val, lbl) in zip([c1,c2,c3,c4,c5], metric_data):
        with col:
            st.markdown(f'<div class="metric-box"><div class="val">{val}</div><div class="lbl">{lbl}</div></div>', unsafe_allow_html=True)

    st.markdown("")

    # ── Recommendations ──
    if score_data["recommendations"]:
        st.markdown("#### 🎯 Recommendations")
        for rec in score_data["recommendations"]:
            st.warning(f"⚠️ {rec}")

    # ── Strength distribution ──
    if decrypted:
        st.markdown("#### 📈 Password Strength Distribution")
        bins = {"Very Weak": 0, "Weak": 0, "Fair": 0, "Strong": 0, "Very Strong": 0}
        for d in decrypted:
            label = password_strength(d["password"])["label"]
            bins[label] = bins.get(label, 0) + 1

        bar_data = {k: v for k, v in bins.items() if v > 0}
        if bar_data:
            st.bar_chart(bar_data)

        # ── Category breakdown ──
        st.markdown("#### 🏷️ Credentials by Category")
        cat_counts: dict = {}
        for d in decrypted:
            cat = d.get("category", "General")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        if cat_counts:
            st.bar_chart(cat_counts)

    # ── Weak password list ──
    if weak_creds:
        st.markdown("#### 🔴 Weak Passwords (Needs Attention)")
        for wc in weak_creds:
            info = password_strength(wc["password"])
            st.markdown(f"""
            <div class="vault-card" style="border-left: 3px solid var(--danger)">
              <strong>{wc['website']}</strong>
              &nbsp; <span class="badge badge-danger">{info['label']} — {info['score']}/100</span>
            </div>
            """, unsafe_allow_html=True)

    # ── Reused passwords ──
    if reused_map:
        st.markdown("#### 🔄 Reused Passwords")
        for pwd, sites in reused_map.items():
            sites_str = ", ".join(sites)
            st.markdown(f"""
            <div class="vault-card" style="border-left: 3px solid var(--warn)">
              <span class="badge badge-warn">Reused on {len(sites)} sites</span>
              <div style="color:var(--muted); font-size:0.85rem; margin-top:6px">{sites_str}</div>
            </div>
            """, unsafe_allow_html=True)


# ─── Audit Log Page ───────────────────────────────────────────────────────────

def page_audit():
    st.markdown('<div class="page-title">📋 Audit Log</div>', unsafe_allow_html=True)
    st.markdown("Immutable security event history")
    st.divider()

    user_id = auth.get_user_id()
    logs    = db.get_audit_log(user_id, limit=100)

    if not logs:
        st.info("No audit events recorded yet.")
        return

    st.caption(f"Showing last {len(logs)} events")

    event_colors = {
        "LOGIN_SUCCESS":    ("badge-success", "✅"),
        "LOGIN_FAILED":     ("badge-danger",  "❌"),
        "USER_CREATED":     ("badge-accent",  "👤"),
        "CREDENTIAL_ADDED": ("badge-accent",  "➕"),
        "CREDENTIAL_UPDATED":("badge-warn",   "✏️"),
        "CREDENTIAL_DELETED":("badge-danger", "🗑️"),
    }

    for log in logs:
        badge_cls, icon = event_colors.get(log["event"], ("badge-accent", "📌"))
        st.markdown(f"""
        <div class="vault-card">
          <span class="badge {badge_cls}">{icon} {log['event']}</span>
          &nbsp; <small style="color:var(--muted)">{log['ts']}</small>
          {f'<div style="color:var(--muted); font-size:0.8rem; margin-top:4px">{log["detail"]}</div>' if log.get("detail") else ''}
        </div>
        """, unsafe_allow_html=True)


# ─── Router ──────────────────────────────────────────────────────────────────

def main():
    render_sidebar()
    auth._init_session()

    if not auth.is_authenticated():
        page_auth()
        return

    page = st.session_state.get("current_page", "vault")

    pages = {
        "vault":     page_vault,
        "add":       page_add_credential,
        "generator": page_generator,
        "advisor":   page_ai_advisor,
        "dashboard": page_dashboard,
        "audit":     page_audit,
    }
    pages.get(page, page_vault)()


if __name__ == "__main__":
    main()
