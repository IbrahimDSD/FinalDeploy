import streamlit as st
import pandas as pd
import numpy as np
import sqlite3
from datetime import datetime
from passlib.hash import pbkdf2_sha256
from sqlalchemy import create_engine, text
from collections import deque
from sqlalchemy.exc import SQLAlchemyError
from urllib.parse import quote_plus
import streamlit.components.v1 as components
import time


# ----------------- Helper: Rerun Function -----------------
def rerun():
    st.rerun()


# ----------------- User Database Configuration -----------------
USER_DB = "user_management.db"


def init_user_db():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    # إنشاء جدول المستخدمين إذا لم يكن موجوداً
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password_hash TEXT,
                  role TEXT,
                  full_name TEXT,
                  force_password_change INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    # إنشاء جدول تقارير زمن إنشاء التقارير
    c.execute('''CREATE TABLE IF NOT EXISTS report_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  duration REAL,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()

    # التأكد من وجود عمود force_password_change
    c.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in c.fetchall()]
    if 'force_password_change' not in cols:
        c.execute("ALTER TABLE users ADD COLUMN force_password_change INTEGER DEFAULT 0")
        conn.commit()

    # إنشاء مستخدم admin افتراضي إذا لم يكن موجوداً
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    admin = c.fetchone()
    if not admin:
        default_password = "admin123"
        hashed_pw = pbkdf2_sha256.hash(default_password)
        c.execute(
            "INSERT INTO users (username, password_hash, role, full_name, force_password_change) VALUES (?, ?, ?, ?, 1)",
            ("admin", hashed_pw, "admin", "System Admin")
        )
        conn.commit()
    conn.close()


init_user_db()


# ----------------- User Management Functions -----------------
def create_user(username, password, role, full_name):
    hashed_pw = pbkdf2_sha256.hash(password)
    try:
        conn = sqlite3.connect(USER_DB)
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, password_hash, role, full_name, force_password_change) VALUES (?, ?, ?, ?, 1)",
            (username, hashed_pw, role, full_name)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def reset_user_password(user_id, new_password):
    hashed_pw = pbkdf2_sha256.hash(new_password)
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute(
        "UPDATE users SET password_hash = ?, force_password_change = 1 WHERE id = ?",
        (hashed_pw, user_id))
    conn.commit()
    conn.close()


def delete_user(user_id):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    # حذف تقارير المستخدم أولاً
    c.execute("DELETE FROM report_logs WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_all_users():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute("SELECT id, username, role, full_name FROM users")
    users = c.fetchall()
    conn.close()
    return users


def verify_user(username, password):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute(
        "SELECT id, password_hash, role, force_password_change FROM users WHERE username = ?",
        (username,))
    result = c.fetchone()
    conn.close()
    if result and pbkdf2_sha256.verify(password, result[1]):
        user_id, _, role, force_flag = result
        return user_id, role, bool(force_flag)
    return None, None, False


def change_password(user_id, new_password):
    hashed_pw = pbkdf2_sha256.hash(new_password)
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute(
        "UPDATE users SET password_hash = ?, force_password_change = 0 WHERE id = ?",
        (hashed_pw, user_id))
    conn.commit()
    conn.close()


# ----------------- Report Logging Functions -----------------
def log_report_generation(user_id, duration):
    """تسجيل زمن إنشاء التقرير."""
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute("INSERT INTO report_logs (user_id, duration) VALUES (?, ?)", (user_id, duration))
    conn.commit()
    conn.close()


def get_report_summary():
    """استرجاع ملخص زمن إنشاء التقارير لكل مستخدم."""
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute("""
        SELECT u.username, AVG(r.duration), SUM(r.duration), COUNT(r.id)
        FROM report_logs r
        JOIN users u ON r.user_id = u.id
        GROUP BY u.username
    """)
    summary = c.fetchall()
    conn.close()
    return summary


# ----------------- Application Database Configuration -----------------
def create_db_engine():
    """إنشاء محرك اتصال بقاعدة البيانات."""
    try:
        server = "52.48.117.197"
        database = "R1029"
        username = "sa"
        password = "Argus@NEG"
        driver = "ODBC Driver 17 for SQL Server"
        connection_string = f"DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD={password};TrustServerCertificate=Yes;Connection Timeout=60"
        encoded_connection = quote_plus(connection_string)
        engine = create_engine(f"mssql+pyodbc:///?odbc_connect={encoded_connection}")
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return engine, None
    except Exception as e:
        return None, str(e)


# ----------------- Data Fetching -----------------
@st.cache_data(ttl=600)
def fetch_data(query, params=None):
    engine, error = create_db_engine()
    if error:
        st.error(f"❌ Database connection failed: {error}")
        return None
    try:
        with engine.connect() as conn:
            return pd.read_sql(text(query), conn, params=params)
    except SQLAlchemyError as e:
        st.error(f"❌ Error fetching data: {e}")
        return None


# ----------------- Business Logic Functions -----------------
def calculate_vat(row):
    if row['currencyid'] == 2:
        return row['amount'] * 11.18
    elif row['currencyid'] == 3:
        return row['amount'] * 7.45
    return 0.0


def convert_gold(row):
    if row['reference'].startswith('S'):
        qty = row.get('qty', np.nan)
        if pd.isna(qty):
            qty = row['amount']
        if row['currencyid'] == 3:
            return qty
        elif row['currencyid'] == 2:
            return qty * 6 / 7
        elif row['currencyid'] == 14:
            return qty * 14 / 21
        elif row['currencyid'] == 4:
            return qty * 24 / 21
    else:
        if row['currencyid'] == 2:
            return row['amount'] * 6 / 7
        elif row['currencyid'] == 4:
            return row['amount'] * 24 / 21
    return row['amount']


def process_fifo(debits, credits):
    """معالجة FIFO بسيطة لإرجاع المعاملات المجمعة النهائية."""
    debits_q = deque(debits)
    history = []
    for credit in sorted(credits, key=lambda x: x['date']):
        rem = credit['amount']
        while rem > 0 and debits_q:
            d = debits_q[0]
            apply_amt = min(rem, d['remaining'])
            d['remaining'] -= apply_amt
            rem -= apply_amt
            if d['remaining'] <= 0:
                d['paid_date'] = credit['date']
                history.append(debits_q.popleft())
    history.extend([d for d in debits_q if d['remaining'] > 0])
    return history


def process_report(df, currency_type):
    df['date'] = pd.to_datetime(df['date'], errors='coerce').dt.floor('D')
    df['paid_date'] = pd.to_datetime(df['paid_date'], errors='coerce').dt.floor('D')
    df['aging_days'] = np.where(df['paid_date'].isna(), '-',
                                (df['paid_date'] - df['date']).dt.days.fillna(0).astype(int))
    for col in ['amount', 'remaining', 'vat_amount']:
        df[col] = df[col].round(2)
    df['paid_date'] = df.apply(lambda r: r['paid_date'].strftime('%Y-%m-%d')
    if pd.notna(r['paid_date']) else 'Unpaid', axis=1)
    df['date'] = df['date'].dt.strftime('%Y-%m-%d')
    suffix = '_gold' if currency_type != 1 else '_cash'
    return df.rename(columns={'date': 'date', 'reference': 'reference'}).add_suffix(suffix).rename(
        columns={f'date{suffix}': 'date', f'reference{suffix}': 'reference'})


def process_transactions(raw, discounts, extras, start_date):
    if raw.empty:
        return pd.DataFrame()

    def calc_row(r):
        base = r['baseAmount'] + r['basevatamount']
        if pd.to_datetime(r['date']) >= start_date:
            disc = discounts.get(r['categoryid'], 0)
            extra = extras.get(r['CategoryParent'], 0)
            return base - (disc * r['qty']) - (extra * r['qty'])
        return base

    def group_fn(g):
        fr = g.iloc[0]
        ref, cur, orig = fr['reference'], fr['currencyid'], fr['amount']
        if ref.startswith('S') and cur == 1:
            valid = g[~g['baseAmount'].isna()].copy()
            valid['final'] = valid.apply(calc_row, axis=1)
            amt = valid['final'].sum()
        else:
            amt = orig
        return pd.Series({'date': fr['date'], 'reference': ref,
                          'currencyid': cur, 'amount': amt, 'original_amount': orig})

    grp = raw.groupby(['functionid', 'recordid', 'date', 'reference', 'currencyid', 'amount'])
    txs = grp.apply(group_fn).reset_index(drop=True)
    txs['date'] = pd.to_datetime(txs['date'])
    txs['converted'] = txs.apply(convert_gold, axis=1)
    return txs


def calculate_aging_reports(transactions):
    """حساب تقرير Aging المُجمّع باستخدام FIFO."""
    cash_debits, cash_credits, gold_debits, gold_credits = [], [], [], []
    transactions['vat_amount'] = transactions.apply(calculate_vat, axis=1)
    transactions['converted'] = transactions.apply(convert_gold, axis=1)
    for _, r in transactions.iterrows():
        entry = {'date': r['date'], 'reference': r['reference'],
                 'amount': abs(r['converted']), 'remaining': abs(r['converted']),
                 'paid_date': None, 'vat_amount': r['vat_amount']}
        if r['currencyid'] == 1:
            (cash_debits if r['amount'] > 0 else cash_credits).append(entry)
        else:
            (gold_debits if r['amount'] > 0 else gold_credits).append(entry)
    cash = process_fifo(sorted(cash_debits, key=lambda x: x['date']), cash_credits)
    gold = process_fifo(sorted(gold_debits, key=lambda x: x['date']), gold_credits)
    cash_df = process_report(pd.DataFrame(cash), 1)
    gold_df = process_report(pd.DataFrame(gold), 2)
    df = pd.merge(cash_df, gold_df, on=['date', 'reference'], how='outer').fillna({
        'amount_cash': 0, 'remaining_cash': 0, 'paid_date_cash': 'Unpaid', 'aging_days_cash': '-', 'vat_amount_cash': 0,
        'amount_gold': 0, 'remaining_gold': 0, 'paid_date_gold': 'Unpaid', 'aging_days_gold': '-', 'vat_amount_gold': 0
    })
    return df[['date', 'reference', 'amount_cash', 'remaining_cash', 'paid_date_cash', 'aging_days_cash',
               'amount_gold', 'remaining_gold', 'paid_date_gold', 'aging_days_gold']]


# ----------------- New Function: Detailed FIFO Processing -----------------
def process_fifo_detailed(debits, credits):
    """
    محاكاة FIFO وتسجيل كل عملية تخصيص دفع (القسط) كحدث منفصل.
    كل حدث يتضمن:
      - date: تاريخ الفاتورة
      - reference: مرجع الفاتورة
      - currencyid: 1 للنقد، وإلا للذهب
      - invoice_amount: المبلغ الأصلي للفاتورة
      - applied: المبلغ المخصوم في هذا الحدث
      - remaining: الرصيد المتبقي بعد هذا الحدث
      - paid_date: التاريخ الذي تم فيه تطبيق الدفع (None إذا لم يتم الدفع)
      - aging_days: عدد الأيام بين الفاتورة والدفع (أو اليوم إذا لم يُدفع)
    """
    debits_q = deque(debits)
    detailed = []
    sorted_credits = sorted(credits, key=lambda x: x['date'])
    for credit in sorted_credits:
        rem_credit = credit['amount']
        while rem_credit > 0 and debits_q:
            d = debits_q[0]
            applied = min(rem_credit, d['remaining'])
            d['remaining'] -= applied
            rem_credit -= applied
            event = {
                'date': d['date'],
                'reference': d['reference'],
                'currencyid': d['currencyid'],
                'invoice_amount': d['amount'],
                'applied': applied,
                'remaining': d['remaining'],
                'paid_date': credit['date'],
                'aging_days': (credit['date'] - d['date']).days
            }
            detailed.append(event)
            if d['remaining'] == 0:
                debits_q.popleft()
    today = pd.Timestamp(datetime.now().date())
    while debits_q:
        d = debits_q.popleft()
        event = {
            'date': d['date'],
            'reference': d['reference'],
            'currencyid': d['currencyid'],
            'invoice_amount': d['amount'],
            'applied': 0,
            'remaining': d['remaining'],
            'paid_date': None,
            'aging_days': (today - d['date']).days
        }
        detailed.append(event)
    return detailed


# ----------------- Authentication Components -----------------
def login_form():
    st.title("🔐 Invoice Aging System")
    with st.form("Login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            uid, role, force = verify_user(username, password)
            if role:
                st.session_state.logged_in = True
                st.session_state.user_id = uid
                st.session_state.username = username
                st.session_state.role = role
                st.session_state.force_password_change = force
                return True
            else:
                st.error("Invalid username or password")
                return False
    return False


def password_change_form():
    st.title("🔑 Change Your Password")
    st.write("You must change your password before continuing.")
    with st.form("ChangePassword"):
        new_pw = st.text_input("New Password", type="password")
        confirm_pw = st.text_input("Confirm Password", type="password")
        if st.form_submit_button("Update Password"):
            if not new_pw or new_pw != confirm_pw:
                st.error("Passwords do not match or are empty.")
            else:
                change_password(st.session_state.user_id, new_pw)
                st.success("Password updated! Please log in again.")
                for k in list(st.session_state.keys()):
                    del st.session_state[k]
                rerun()


# ----------------- User Management Interface -----------------
def user_management():
    st.sidebar.header("👥 User Management")
    with st.sidebar.expander("➕ Add New User"):
        with st.form("Add User"):
            new_username = st.text_input("Username", key="new_user")
            new_password = st.text_input("Password", type="password", key="new_pass")
            new_role = st.selectbox("Role", ["admin", "user"], key="new_role")
            new_fullname = st.text_input("Full Name", key="new_name")
            if st.form_submit_button("Create User"):
                if create_user(new_username, new_password, new_role, new_fullname):
                    st.success("✅ User created successfully. They will be prompted to change password on first login.")
                else:
                    st.error("❌ Username already exists")
    with st.sidebar.expander("🔄 Reset User Password"):
        users = get_all_users()
        options = [f"{u[1]} ({u[3]})" for u in users]
        selected = st.selectbox("Select user", options, key="reset_user")
        new_pw = st.text_input("New Password", type="password", key="reset_pw")
        if st.button("Reset Password"):
            uid = [u[0] for u in users if f"{u[1]} ({u[3]})" == selected][0]
            if new_pw:
                reset_user_password(uid, new_pw)
                st.success("✅ Password reset. User must change password at next login.")
            else:
                st.error("Enter a new password to reset.")
    with st.sidebar.expander("➖ Remove User"):
        users = get_all_users()
        if users:
            user_list = [f"{u[1]} ({u[3]})" for u in users if u[1] != st.session_state.username]
            selected_user = st.selectbox("Select user to remove", user_list, key="del_user")
            if st.button("Delete User"):
                user_id = [u[0] for u in users if f"{u[1]} ({u[3]})" == selected_user][0]
                delete_user(user_id)
                rerun()
        else:
            st.write("No users to display")
    with st.sidebar.expander("📊 Report Generation Summary"):
        summary = get_report_summary()
        if summary:
            df = pd.DataFrame(
                summary,
                columns=['Username', 'Average Duration (s)', 'Total Duration (s)', 'Number of Reports']
            )
            st.dataframe(df)
        else:
            st.write("No logs available.")


# ----------------- Main Application -----------------
def main_app():
    if st.session_state.get('force_password_change', False):
        password_change_form()
        return

    st.set_page_config(page_title="Invoice Aging System", layout="wide")
    if st.session_state.role == "admin":
        user_management()
    with st.sidebar:
        st.write(f"👤 Logged in as: {st.session_state.username} ({st.session_state.role})")
        if st.button("🚪 Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            rerun()

    st.title("📊 Aging Report")

    # إدخال حد الـ Aging Days من الشريط الجانبي (هذا الحد يستخدم للتلوين والتصفية في التقارير)
    aging_threshold = st.sidebar.number_input("Enter Aging Days Threshold", min_value=0, value=30, step=1)

    groups = fetch_data("SELECT recordid, name FROM figrp ORDER BY name")
    if groups is None or groups.empty:
        st.error("❌ No groups found or an error occurred while fetching groups.")
        return

    customers = fetch_data("SELECT recordid, name, reference FROM fiacc WHERE groupid = 1")
    cust_list = ["Select Customer..."] + [f"{r['name']} ({r['reference']})" for _, r in customers.iterrows()]
    selected_customer = st.sidebar.selectbox("Customer Name", cust_list)
    start_date = st.sidebar.date_input("Start Date", datetime.now().replace(day=1))
    end_date = st.sidebar.date_input("End Date", datetime.now())
    st.sidebar.header("Category Discounts")
    discount_50 = st.sidebar.number_input("احجار عيار 21", 0.0, 1000.0, 0.0)
    discount_61 = st.sidebar.number_input("سادة عيار 21", 0.0, 1000.0, 0.0)
    discount_47 = st.sidebar.number_input("ذهب مشغول عيار 18", 0.0, 1000.0, 0.0)
    discount_62 = st.sidebar.number_input("سادة عيار 18", 0.0, 1000.0, 0.0)
    discount_48 = st.sidebar.number_input("Estar G18", 0.0, 1000.0, 0.0)
    discount_45 = st.sidebar.number_input("تعجيل دفع عيار 21", 0.0, 1000.0, 0.0)
    discount_46 = st.sidebar.number_input("تعجيل دفع عيار 18", 0.0, 1000.0, 0.0)

    if st.sidebar.button("Generate Report"):
        if selected_customer == "Select Customer...":
            st.error("Please select a customer.")
            return
        cid = int(customers.iloc[cust_list.index(selected_customer) - 1]['recordid'])
        query = """
            SELECT f.functionid, f.recordid, f.date, f.reference, f.currencyid, f.amount,
                   s.baseAmount, s.baseDiscount, s.basevatamount, s.qty,
                   ivca.recordid as categoryid, ivca.parentid as CategoryParent
            FROM fitrx f
            LEFT JOIN satrx s ON f.functionid = s.functionid AND f.recordid = s.recordid
            LEFT JOIN ivit ON s.itemid = ivit.recordid
            LEFT JOIN ivca ON ivit.categoryid = ivca.recordid
            WHERE f.accountid = :acc
        """
        start_time = time.time()  # Start measuring time
        raw = fetch_data(query, {"acc": cid})
        if raw is None or raw.empty:
            st.warning("No transactions found for the given customer ID.")
            return
        discounts = {50: discount_50, 47: discount_47, 61: discount_61, 62: discount_62, 48: discount_48}
        extras = {45: discount_45, 46: discount_46}
        start_date_dt = pd.to_datetime(start_date)
        txs = process_transactions(raw, discounts, extras, start_date_dt)
        if txs.empty:
            st.warning("No transactions to process.")
            return

        # --- Aggregated Aging Report ---
        report = calculate_aging_reports(txs)
        report['date_dt'] = pd.to_datetime(report['date'])
        report = report[(report['date_dt'] >= start_date_dt) & (report['date_dt'] <= pd.to_datetime(end_date))]
        report = report.sort_values(by=['date_dt', 'reference'], ascending=[True, True]).reset_index(drop=True)
        report = report.drop(columns=['date_dt'])
        end_time = time.time()
        duration = end_time - start_time
        log_report_generation(st.session_state.user_id, duration)

        # دالة لتلوين الصفوف بناءً على شرط aging_days
        def highlight_row(row):
            styles = [''] * len(row)
            try:
                cash = int(row['aging_days_cash']) if row['aging_days_cash'] != '-' else 0
            except:
                cash = 0
            try:
                gold = int(row['aging_days_gold']) if row['aging_days_gold'] != '-' else 0
            except:
                gold = 0
            # إذا كانت كل من قيمة النقدي والذهبي أكبر من الحد، يتم تلوين الصف بأكمله
            if cash > aging_threshold and gold > aging_threshold:
                styles = ['background-color: green'] * len(row)
            else:
                # إذا كان فقط النقدي أكبر من الحد
                if cash > aging_threshold:
                    idx = row.index.get_loc('aging_days_cash')
                    styles[idx] = 'background-color: green'
                # إذا كان فقط الذهبي أكبر من الحد
                if gold > aging_threshold:
                    idx = row.index.get_loc('aging_days_gold')
                    styles[idx] = 'background-color: green'
            return styles

        styled_report = report.style.apply(highlight_row, axis=1)
        st.subheader("Aging Report")
        st.dataframe(styled_report, use_container_width=True)
        col1, col2 = st.columns(2)
        with col1:
            csv = report.to_csv(index=False, encoding='utf-8-sig').encode('utf-8-sig')
            st.download_button(
                "Download Full Report",
                csv,
                file_name=f"Aging_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
        with col2:
            if st.button("🖨️ Print Report"):
                st.markdown("""
                    <script>
                        window.print();
                    </script>
                """, unsafe_allow_html=True)
        components.html("""
        <div id="printTrigger"></div>
        <script>
            function handlePrint() {
                const btn = document.createElement('button');
                btn.style.display = 'none';
                btn.onclick = () => window.print();
                document.body.appendChild(btn);
                btn.click();
                btn.remove();
            }
            window.addEventListener('DOMContentLoaded', () => {
                const printBtn = document.querySelector('[data-testid="stButton"]');
                if(printBtn) {
                    printBtn.addEventListener('click', handlePrint);
                }
            });
        </script>
        """, height=0, width=0)

        # --- Detailed Installments Search by Reference ---
        st.markdown("---")
        st.subheader("تفاصيل سداد فاتورة معينة")
        st.write("أدخل الـ reference الخاص بالفاتورة ")
        search_ref = st.text_input("أدخل reference للفاتورة:", value="")

        # Build detailed FIFO events for installments using opening balances and transactions
        cash_debits, cash_credits, gold_debits, gold_credits = [], [], [], []
        fioba = fetch_data(
            "SELECT fiscalYear, currencyid, amount FROM fioba WHERE fiscalYear = 2023 AND accountId = :acc",
            {"acc": cid}
        )
        if fioba is not None and not fioba.empty:
            for _, r in fioba.iterrows():
                entry_date = pd.to_datetime(f"{int(r['fiscalYear'])}-01-01")
                conv = r['amount']
                if r['currencyid'] != 1:
                    conv = convert_gold({
                        'reference': '',
                        'amount': r['amount'],
                        'currencyid': r['currencyid']
                    })
                entry = {
                    'date': entry_date,
                    'reference': 'Opening-Balance-2023',
                    'currencyid': r['currencyid'],
                    'amount': conv,
                    'remaining': conv
                }
                if r['currencyid'] == 1:
                    cash_debits.append(entry)
                else:
                    gold_debits.append(entry)
        for _, r in txs.iterrows():
            entry = {
                'date': r['date'],
                'reference': r['reference'],
                'currencyid': r['currencyid'],
                'amount': abs(r['converted']),
                'remaining': abs(r['converted'])
            }
            if r['amount'] > 0:
                if r['currencyid'] == 1:
                    cash_debits.append(entry)
                else:
                    gold_debits.append(entry)
            else:
                if r['currencyid'] == 1:
                    cash_credits.append({'date': r['date'], 'amount': abs(r['converted'])})
                else:
                    gold_credits.append({'date': r['date'], 'amount': abs(r['converted'])})
        # Process detailed FIFO events for both cash and gold
        cash_details = process_fifo_detailed(sorted(cash_debits, key=lambda x: x['date']),
                                             sorted(cash_credits, key=lambda x: x['date']))
        gold_details = process_fifo_detailed(sorted(gold_debits, key=lambda x: x['date']),
                                             sorted(gold_credits, key=lambda x: x['date']))
        # Convert the detailed events into DataFrames
        cash_details_df = pd.DataFrame(cash_details)
        gold_details_df = pd.DataFrame(gold_details)

        # تطبيق فلتر التاريخ على التفاصيل
        if not cash_details_df.empty:
            cash_details_df['date'] = pd.to_datetime(cash_details_df['date'])
            cash_details_df = cash_details_df[(cash_details_df['date'] >= pd.to_datetime(start_date)) &
                                              (cash_details_df['date'] <= pd.to_datetime(end_date))]
        if not gold_details_df.empty:
            gold_details_df['date'] = pd.to_datetime(gold_details_df['date'])
            gold_details_df = gold_details_df[(gold_details_df['date'] >= pd.to_datetime(start_date)) &
                                              (gold_details_df['date'] <= pd.to_datetime(end_date))]

        # تطبيق البحث على كل DataFrame على حدة
        if search_ref.strip() != "":
            cash_details_df = cash_details_df[
                cash_details_df['reference'].str.contains(search_ref, case=False, na=False)]
            gold_details_df = gold_details_df[
                gold_details_df['reference'].str.contains(search_ref, case=False, na=False)]

        # تصفية التفاصيل بحيث تُعرض فقط الفواتير التي aging_days أكبر من القيمة المُدخلة
        if not cash_details_df.empty:
            cash_details_df = cash_details_df[cash_details_df['aging_days'] > aging_threshold]
        if not gold_details_df.empty:
            gold_details_df = gold_details_df[gold_details_df['aging_days'] > aging_threshold]

        # تنسيق عمود التاريخ لعرض أفضل
        if not cash_details_df.empty:
            cash_details_df['Invoice Date'] = cash_details_df['date'].dt.strftime('%Y-%m-%d')
            cash_details_df['Paid Date'] = cash_details_df['paid_date'].apply(
                lambda d: d.strftime('%Y-%m-%d') if pd.notna(d) else "Unpaid")
        if not gold_details_df.empty:
            gold_details_df['Invoice Date'] = gold_details_df['date'].dt.strftime('%Y-%m-%d')
            gold_details_df['Paid Date'] = gold_details_df['paid_date'].apply(
                lambda d: d.strftime('%Y-%m-%d') if pd.notna(d) else "Unpaid")

        st.markdown("### تفاصيل السداد نقدًا")
        if not cash_details_df.empty:
            st.dataframe(cash_details_df[
                             ['Invoice Date', 'reference', 'invoice_amount', 'applied', 'remaining', 'Paid Date',
                              'aging_days']].reset_index(drop=True),
                         use_container_width=True)
        else:
            st.info("لا توجد بيانات سداد نقداً لهذه الفاتورة (أو لا تحقق شرط aging_days > threshold).")

        st.markdown("### تفاصيل السداد ذهباً")
        if not gold_details_df.empty:
            st.dataframe(gold_details_df[
                             ['Invoice Date', 'reference', 'invoice_amount', 'applied', 'remaining', 'Paid Date',
                              'aging_days']].reset_index(drop=True),
                         use_container_width=True)
        else:
            st.info("لا توجد بيانات سداد ذهباً لهذه الفاتورة (أو لا تحقق شرط aging_days > threshold).")


# ----------------- Entry Point -----------------
if __name__ == "__main__":
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if st.session_state.logged_in:
        main_app()
    else:
        if login_form():
            st.rerun()
