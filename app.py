"""
Multi-Company Study Abroad Lead Management SaaS
Flask Application - Main File

This application manages leads for multiple study abroad consultancies.
Each company has its own database and users cannot see other companies' data.
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from functools import wraps
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
import psycopg2
import os
import csv
import io
import secrets
import logging

# Load .env when running locally. On Render, env vars are injected directly
# so dotenv is a harmless no-op even if the package is present.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; env vars must be set externally

# ============================================================================
# APPLICATION SETUP
# ============================================================================

app = Flask(__name__)

# ============================================================
# SECURITY CONFIGURATION
# ============================================================
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    raise RuntimeError(
        "SECRET_KEY is not set. Add it to .env (local) or Render environment (production)."
    )
app.secret_key = _secret_key
app.config['SESSION_COOKIE_NAME'] = 'lms_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Secure cookies require HTTPS — use on Render, not locally
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Create necessary folders
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

# ============================================================
# DATABASE CONNECTION POOL
# ============================================================
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. Add it to .env (local) or Render environment (production)."
    )

connection_pool = None

def init_connection_pool():
    global connection_pool
    try:
        connection_pool = pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=10,
            dsn=DATABASE_URL,
            cursor_factory=RealDictCursor
        )
        print("✅ Connection pool initialized")
    except Exception as e:
        print(f"❌ Connection pool error: {e}")

def get_db_connection():
    global connection_pool
    if connection_pool is None:
        init_connection_pool()
    return connection_pool.getconn()

def release_db_connection(conn):
    """Return connection to pool, or close if not from pool"""
    global connection_pool
    if conn is None:
        return
    try:
        if connection_pool:
            connection_pool.putconn(conn)
        else:
            conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass

# ============================================================================
# DATE FORMAT SETUP
# ============================================================================

@app.template_filter('ddmmyyyy')
def format_date_ddmmyyyy(date_string):
    """Convert date/datetime to dd/mm/yyyy format - handles PostgreSQL datetime objects"""
    if not date_string:
        return ''
    try:
        # Handle PostgreSQL datetime/date objects directly
        if hasattr(date_string, 'strftime'):
            return date_string.strftime('%d/%m/%Y')
        # Handle string formats
        date_string = str(date_string)
        if len(date_string) >= 10:
            dt = datetime.strptime(date_string[:10], '%Y-%m-%d')
            return dt.strftime('%d/%m/%Y')
        return date_string
    except:
        return str(date_string)


# ============================================================
# SIMPLE CSRF PROTECTION
# ============================================================
@app.before_request
def csrf_protect():
    """Basic CSRF protection for state-changing requests"""
    if request.method == "POST":
        # Skip CSRF check for login and developer routes (no session yet)
        skip_routes = ['login', 'signup', 'developer_login', 'landing', 'super_admin_reset_password',
                       'student_portal', 'portal_upload_document']
        if request.endpoint in skip_routes:
            return None
        
        token = session.get('csrf_token')
        form_token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        
        if not token or token != form_token:
            flash('Security validation failed. Please try again.', 'error')
            return redirect(request.referrer or url_for('dashboard'))

@app.context_processor
def inject_csrf_token():
    """Inject CSRF token into all templates"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return dict(csrf_token=session['csrf_token'])


@app.context_processor
def inject_notification_count():
    """Inject unread notification count into every template for navbar badge."""
    if session.get('user_id') and session.get('company_id'):
        count = get_unread_notification_count(session['company_id'], session['user_id'])
        return dict(unread_notification_count=count)
    return dict(unread_notification_count=0)


# ============================================================================
# INTAKE URGENCY HELPER  (Jinja2 global so templates can call it directly)
# ============================================================================

# Approximate intake start dates per country: (month, day, short_label)
_INTAKE_WINDOWS = {
    # English-speaking destinations
    'UK':          [(1, 15, 'Jan'), (5, 1, 'May'), (9, 1, 'Sep')],
    'Australia':   [(2, 1, 'Feb'), (7, 1, 'Jul'), (11, 1, 'Nov')],
    'Canada':      [(1, 1, 'Jan'), (5, 1, 'May'), (9, 1, 'Sep')],
    'USA':         [(1, 15, 'Jan'), (8, 15, 'Aug')],
    'New Zealand': [(2, 1, 'Feb'), (7, 1, 'Jul')],
    'Ireland':     [(1, 15, 'Jan'), (9, 1, 'Sep')],
    'Malaysia':    [(3, 1, 'Mar'), (8, 1, 'Aug')],

    # Europe
    'Germany':     [(4, 1, 'Apr'), (10, 1, 'Oct')],
    'Netherlands': [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'France':      [(9, 1, 'Sep')],
    'Spain':       [(1, 15, 'Jan'), (9, 1, 'Sep')],
    'Belgium':     [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Finland':     [(1, 1, 'Jan'), (8, 15, 'Aug')],
    'Italy':       [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Latvia':      [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Bulgaria':    [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Czech Republic': [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Romania':     [(2, 1, 'Feb'), (10, 1, 'Oct')],
    'Moldova':     [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Portugal':    [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Austria':     [(3, 1, 'Mar'), (10, 1, 'Oct')],
    'Hungary':     [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Russia':      [(2, 1, 'Feb'), (9, 1, 'Sep')],

    # Asia
    'China':       [(2, 15, 'Feb'), (9, 1, 'Sep')],
    'Japan':       [(4, 1, 'Apr'), (10, 1, 'Oct')],
    'South Korea': [(3, 1, 'Mar'), (9, 1, 'Sep')],
    'Vietnam':     [(1, 1, 'Jan'), (9, 1, 'Sep')],
    'Philippines': [(1, 1, 'Jan'), (8, 1, 'Aug')],
    'Armenia':     [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Kazakhstan':  [(1, 1, 'Jan'), (9, 1, 'Sep')],
    'Azerbaijan':  [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Georgia':     [(2, 1, 'Feb'), (9, 1, 'Sep')],
    'Uzbekistan':  [(2, 1, 'Feb'), (9, 1, 'Sep')],

    # Middle East
    'UAE':         [(1, 1, 'Jan'), (5, 1, 'May'), (9, 1, 'Sep')],
    'Israel':      [(3, 1, 'Mar'), (10, 1, 'Oct')],
    'Egypt':       [(2, 1, 'Feb'), (9, 1, 'Sep')],
}

# Only flag mid/late-funnel — no point alarming on brand-new cold leads
_INTAKE_ACTIVE_STATUSES = {
    'Interested', 'Follow-up', 'Follow-up Scheduled', 'Registered', 'On-Hold'
}

def _get_intake_urgency(country, lead_status):
    """Return urgency dict if intake is within 75 days, else None."""
    try:
        if not country or lead_status not in _INTAKE_ACTIVE_STATUSES:
            return None
        windows = _INTAKE_WINDOWS.get(country)
        if not windows:
            return None
        today = date.today()
        best = None
        for month, day, label in windows:
            for year_offset in (0, 1):
                try:
                    intake_dt = date(today.year + year_offset, month, day)
                except ValueError:
                    continue
                days_until = (intake_dt - today).days
                if 0 <= days_until <= 75:
                    if best is None or days_until < best['days_until']:
                        best = {
                            'days_until': days_until,
                            'intake_date_str': label,
                            'level': 'critical' if days_until <= 30 else 'warning'
                        }
        return best
    except Exception:
        return None

# Expose to all Jinja2 templates
app.jinja_env.globals['get_intake_urgency'] = _get_intake_urgency

# ============================================================================
# DATABASE HELPER FUNCTIONS
# ============================================================================

def get_master_db():
    """Get connection from pool (master DB - companies, admin tables)"""
    return get_db_connection()

def get_company_db(company_code=None):
    """Get a connection from the shared pool.
    company_code is accepted for call-site compatibility but unused —
    all tenants share one PostgreSQL DB, isolated by company_id in every query."""
    return get_db_connection()


def init_master_db():
    """Initialize the master database with companies table"""
    conn = get_master_db()
    cursor = conn.cursor()
    
    # Create companies table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            id SERIAL PRIMARY KEY,
            company_name TEXT UNIQUE NOT NULL,
            company_code TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'PENDING',
            subscription_start_date DATE,
            subscription_end_date DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create developer admin table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS developer_admin (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    
    # Create default developer admin if not exists.
    # Password comes from DEVELOPER_PASSWORD env var; falls back to a random
    # token (printed once to stdout) so there is never a guessable default.
    cursor.execute("SELECT COUNT(*) as count FROM developer_admin")
    if cursor.fetchone()['count'] == 0:
        dev_password = os.environ.get('DEVELOPER_PASSWORD')
        if not dev_password:
            dev_password = secrets.token_urlsafe(16)
            print(f"⚠️  DEVELOPER_PASSWORD not set. Generated one-time password: {dev_password}")
            print("    Set DEVELOPER_PASSWORD in your .env or Render environment to make it permanent.")
        cursor.execute(
            "INSERT INTO developer_admin (username, password_hash) VALUES (%s, %s)",
            ('admin', generate_password_hash(dev_password))
        )
    
    conn.commit()
    release_db_connection(conn)
    
def init_company_db(company_code):
    """Initialize company tables in PostgreSQL with company_id for multi-tenancy"""
    conn = get_master_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(company_id, email)
    )
    """)
    
    # Courses table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS courses (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        course_name TEXT NOT NULL,
        course_fee NUMERIC(12,2) NOT NULL,
        course_duration TEXT,
        course_details_1_link TEXT,
        course_details_2_link TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Leads table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS leads (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        assigned_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
        serial_number INTEGER,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        whatsapp TEXT,
        email TEXT,
        highest_qualification TEXT,
        location TEXT,
        age INTEGER,
        country_preference TEXT,
        course_type TEXT,
        course_level TEXT,
        lead_source TEXT,
        lead_received_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        lead_value NUMERIC(12,2) DEFAULT 0,
        registration_amount NUMERIC(12,2) DEFAULT 0,
        lead_status TEXT DEFAULT 'Not Yet Contacted',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        score INTEGER,
        score_category TEXT,
        score_updated_at TIMESTAMP,
        first_contacted_at TIMESTAMP,
        closed_reason TEXT,
        closed_reason_detail TEXT,
        UNIQUE(company_id, phone)
    )
    """)
    
    # Add score columns if they don't exist (for existing tables)
    cursor.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'leads' AND column_name = 'score'
            ) THEN
                ALTER TABLE leads ADD COLUMN score INTEGER DEFAULT 10;
            END IF;
            
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'leads' AND column_name = 'score_category'
            ) THEN
                ALTER TABLE leads ADD COLUMN score_category TEXT DEFAULT 'Cold';
            END IF;
            
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'leads' AND column_name = 'score_updated_at'
            ) THEN
                ALTER TABLE leads ADD COLUMN score_updated_at TIMESTAMP;
            END IF;
        END $$;
    """)
    
    # Interactions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS interactions (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        contact_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        interaction_type TEXT DEFAULT 'Call',
        interaction_outcome TEXT DEFAULT 'Needs Follow-up',
        interaction_note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Documents table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        document_name TEXT NOT NULL,
        document_link TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Audit logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        lead_id INTEGER REFERENCES leads(id) ON DELETE SET NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT
    )
    """)
    
    # Follow-ups table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS followups (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        followup_date DATE NOT NULL,
        note TEXT,
        completed BOOLEAN DEFAULT FALSE,
        followup_escalated BOOLEAN DEFAULT FALSE,
        escalated_at TIMESTAMP,
        escalation_acknowledged BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Pipeline stage probabilities table (Tier 2-G)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pipeline_stage_probabilities (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        stage TEXT NOT NULL,
        probability INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(company_id, stage)
    )
    """)

    # Lead source budgets table (Tier 3-J)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS lead_source_budgets (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        source TEXT NOT NULL,
        month DATE NOT NULL,
        budget_spent NUMERIC(12,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(company_id, source, month)
    )
    """)

    # Stale lead reassignment rules table (Tier 3-K)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS stale_lead_rules (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        days_threshold INTEGER NOT NULL DEFAULT 14,
        auto_reassign_to_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        enabled BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(company_id)
    )
    """)

    # Internal notifications table (Tier 4)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        lead_id INTEGER REFERENCES leads(id) ON DELETE SET NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Student self-serve portal table (Tier 4)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS student_portals (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_accessed_at TIMESTAMP,
        UNIQUE(company_id, lead_id)
    )
    """)

    # Incentive targets table (Tier 5)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incentive_targets (
        id SERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        period_type TEXT NOT NULL,
        period_start DATE NOT NULL,
        period_end DATE NOT NULL,
        registration_target INTEGER NOT NULL DEFAULT 0,
        won_target INTEGER NOT NULL DEFAULT 0,
        label TEXT,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE
    )
    """)

    # Incentive tiers per target (Tier 5)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incentive_tiers (
        id SERIAL PRIMARY KEY,
        target_id INTEGER NOT NULL REFERENCES incentive_targets(id) ON DELETE CASCADE,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        tier_label TEXT NOT NULL,
        threshold_percent INTEGER NOT NULL,
        incentive_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    release_db_connection(conn)


def migrate_databases():
    """Add missing columns to PostgreSQL tables"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check and add lead_source column
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'leads' AND column_name = 'lead_source'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE leads ADD COLUMN lead_source TEXT")
            conn.commit()
            print("✅ Added lead_source column")
        
        # Check and add course_id column
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'leads' AND column_name = 'course_id'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE leads ADD COLUMN course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL")
            conn.commit()
            print("✅ Added course_id column")

        # ── TIER 1 MIGRATIONS ─────────────────────────────────────────────────

        # A: Speed-to-Contact
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'leads' AND column_name = 'first_contacted_at'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE leads ADD COLUMN first_contacted_at TIMESTAMP")
            conn.commit()
            print("✅ Added first_contacted_at column")

        # C: Lost Reason
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'leads' AND column_name = 'closed_reason'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE leads ADD COLUMN closed_reason TEXT")
            cursor.execute("ALTER TABLE leads ADD COLUMN closed_reason_detail TEXT")
            conn.commit()
            print("✅ Added closed_reason columns")

        # B: Structured Interactions — type
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'interactions' AND column_name = 'interaction_type'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE interactions ADD COLUMN interaction_type TEXT DEFAULT 'Call'")
            conn.commit()
            print("✅ Added interaction_type column")

        # B: Structured Interactions — outcome
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'interactions' AND column_name = 'interaction_outcome'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE interactions ADD COLUMN interaction_outcome TEXT DEFAULT 'Needs Follow-up'")
            conn.commit()
            print("✅ Added interaction_outcome column")

        # ── TIER 2 MIGRATIONS ─────────────────────────────────────────────────

        # E: WhatsApp tracking fields
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'leads' AND column_name = 'whatsapp_opt_in'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE leads ADD COLUMN whatsapp_opt_in BOOLEAN DEFAULT TRUE")
            cursor.execute("ALTER TABLE leads ADD COLUMN last_whatsapp_sent_at TIMESTAMP")
            conn.commit()
            print("✅ Added whatsapp tracking columns")

        # F: Overdue follow-up escalation fields
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'followups' AND column_name = 'followup_escalated'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE followups ADD COLUMN followup_escalated BOOLEAN DEFAULT FALSE")
            cursor.execute("ALTER TABLE followups ADD COLUMN escalated_at TIMESTAMP")
            cursor.execute("ALTER TABLE followups ADD COLUMN escalation_acknowledged BOOLEAN DEFAULT FALSE")
            conn.commit()
            print("✅ Added followup escalation columns")

        # G: Pipeline stage probabilities table
        cursor.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'pipeline_stage_probabilities'
        """)
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE pipeline_stage_probabilities (
                    id SERIAL PRIMARY KEY,
                    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                    stage TEXT NOT NULL,
                    probability INTEGER NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(company_id, stage)
                )
            """)
            conn.commit()
            print("✅ Created pipeline_stage_probabilities table")

        # ── TIER 3 MIGRATIONS ─────────────────────────────────────────────────

        # I: Study-abroad specific lead fields
        tier3_lead_fields = [
            ('budget_range',          "TEXT"),
            ('visa_history',          "TEXT"),
            ('ielts_score',           "NUMERIC(3,1)"),
            ('ielts_planned_date',    "DATE"),
            ('preferred_intake',      "TEXT"),
            ('competitor_consulted',  "TEXT"),
            ('referral_name',         "TEXT"),
        ]
        for col, coltype in tier3_lead_fields:
            cursor.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'leads' AND column_name = %s
            """, (col,))
            if not cursor.fetchone():
                cursor.execute(f"ALTER TABLE leads ADD COLUMN {col} {coltype}")
                conn.commit()
                print(f"✅ Added leads.{col}")

        # J: Lead source budgets table
        cursor.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'lead_source_budgets'
        """)
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE lead_source_budgets (
                    id SERIAL PRIMARY KEY,
                    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                    source TEXT NOT NULL,
                    month DATE NOT NULL,
                    budget_spent NUMERIC(12,2) DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(company_id, source, month)
                )
            """)
            conn.commit()
            print("✅ Created lead_source_budgets table")

        # K: Stale lead reassignment rules table
        cursor.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'stale_lead_rules'
        """)
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE stale_lead_rules (
                    id SERIAL PRIMARY KEY,
                    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                    days_threshold INTEGER NOT NULL DEFAULT 14,
                    auto_reassign_to_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(company_id)
                )
            """)
            conn.commit()
            print("✅ Created stale_lead_rules table")

        # ── TIER 4 MIGRATIONS ─────────────────────────────────────────────────

        # Notifications table
        cursor.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'notifications'
        """)
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE notifications (
                    id SERIAL PRIMARY KEY,
                    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    lead_id INTEGER REFERENCES leads(id) ON DELETE SET NULL,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    is_read BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✅ Created notifications table")

        # Student portals table
        cursor.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'student_portals'
        """)
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE student_portals (
                    id SERIAL PRIMARY KEY,
                    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                    lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
                    token TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_accessed_at TIMESTAMP,
                    UNIQUE(company_id, lead_id)
                )
            """)
            conn.commit()
            print("✅ Created student_portals table")

        # ── TIER 5 MIGRATIONS ─────────────────────────────────────────────────

        cursor.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'incentive_targets'
        """)
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE incentive_targets (
                    id SERIAL PRIMARY KEY,
                    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                    period_type TEXT NOT NULL,
                    period_start DATE NOT NULL,
                    period_end DATE NOT NULL,
                    registration_target INTEGER NOT NULL DEFAULT 0,
                    won_target INTEGER NOT NULL DEFAULT 0,
                    label TEXT,
                    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)
            conn.commit()
            print("✅ Created incentive_targets table")

        cursor.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'incentive_tiers'
        """)
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE incentive_tiers (
                    id SERIAL PRIMARY KEY,
                    target_id INTEGER NOT NULL REFERENCES incentive_targets(id) ON DELETE CASCADE,
                    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
                    tier_label TEXT NOT NULL,
                    threshold_percent INTEGER NOT NULL,
                    incentive_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✅ Created incentive_tiers table")

        conn.commit()
        release_db_connection(conn)
        print("✅ Database migration completed")
    except Exception as e:
        print(f"❌ Migration error: {e}")


# ============================================================================
# TIER 4: NOTIFICATION HELPERS
# ============================================================================

def create_notification(company_id, user_id, notif_type, title, body, lead_id=None):
    """
    Insert a notification for a specific user.
    Types: lead_assigned | followup_due | followup_overdue | lead_stale
           portal_upload | escalation | new_lead
    Call this function from any route that needs to fire an alert.
    """
    try:
        conn = get_company_db(company_id)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO notifications (company_id, user_id, lead_id, type, title, body)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (company_id, user_id, lead_id, notif_type, title, body))
        conn.commit()
        release_db_connection(conn)
    except Exception as e:
        print(f"❌ Notification error: {e}")


def create_notification_for_admins(company_id, notif_type, title, body, lead_id=None):
    """
    Broadcast a notification to all super_admins in a company.
    """
    try:
        conn = get_company_db(company_id)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM users WHERE company_id = %s AND role = 'super_admin'",
            (company_id,)
        )
        admins = cursor.fetchall()
        for admin in admins:
            cursor.execute("""
                INSERT INTO notifications (company_id, user_id, lead_id, type, title, body)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (company_id, admin['id'], lead_id, notif_type, title, body))
        conn.commit()
        release_db_connection(conn)
    except Exception as e:
        print(f"❌ Admin notification error: {e}")


def get_unread_notification_count(company_id, user_id):
    """Return unread notification count for a user — used by navbar badge."""
    try:
        conn = get_company_db(company_id)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM notifications WHERE company_id = %s AND user_id = %s AND is_read = FALSE",
            (company_id, user_id)
        )
        result = cursor.fetchone()
        release_db_connection(conn)
        return result['cnt'] if result else 0
    except Exception:
        return 0


# ============================================================================
# INDEX MIGRATION
# ============================================================================

def migrate_indexes():
    """
    Create all required multi-tenant performance indexes.
    Safe to run multiple times (idempotent).
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        logging.info("🔄 Running index migrations...")

        indexes = [
            # Company ID isolation (critical for multi-tenancy)
            "CREATE INDEX IF NOT EXISTS idx_users_company_id ON users(company_id)",
            "CREATE INDEX IF NOT EXISTS idx_courses_company_id ON courses(company_id)",
            "CREATE INDEX IF NOT EXISTS idx_leads_company_id ON leads(company_id)",
            "CREATE INDEX IF NOT EXISTS idx_interactions_company_id ON interactions(company_id)",
            "CREATE INDEX IF NOT EXISTS idx_documents_company_id ON documents(company_id)",
            "CREATE INDEX IF NOT EXISTS idx_followups_company_id ON followups(company_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_company_id ON audit_logs(company_id)",

            # High-frequency lead query indexes
            "CREATE INDEX IF NOT EXISTS idx_leads_company_status ON leads(company_id, lead_status)",
            "CREATE INDEX IF NOT EXISTS idx_leads_company_assigned_user ON leads(company_id, assigned_user_id)",
            "CREATE INDEX IF NOT EXISTS idx_leads_company_created_at ON leads(company_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_leads_company_serial_number ON leads(company_id, serial_number)",

            # Dashboard / follow-up optimisation
            "CREATE INDEX IF NOT EXISTS idx_followups_pending ON followups(company_id, user_id, completed, followup_date)",
            "CREATE INDEX IF NOT EXISTS idx_followups_dashboard ON followups(company_id, followup_date, completed)",

            # Relation lookups
            "CREATE INDEX IF NOT EXISTS idx_interactions_company_lead ON interactions(company_id, lead_id)",
            "CREATE INDEX IF NOT EXISTS idx_documents_company_lead ON documents(company_id, lead_id)",

            # Audit log sorting
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_company_timestamp ON audit_logs(company_id, timestamp DESC)",
        ]

        for sql in indexes:
            cursor.execute(sql)

        conn.commit()
        release_db_connection(conn)
        logging.info("✅ Index migration completed successfully.")

    except Exception as e:
        logging.error(f"❌ Index migration failed: {e}")
        try:
            conn.rollback()
            release_db_connection(conn)
        except Exception:
            pass

# ============================================================
# SIMPLE RATE LIMITING FOR LOGIN
# ============================================================
login_attempts = {}

def check_rate_limit(identifier, max_attempts=5, window_minutes=15):
    """Simple in-memory rate limiting. Use company_code:email as identifier for tenant isolation."""
    now = datetime.now()
    if identifier in login_attempts:
        attempts, first_attempt = login_attempts[identifier]
        window = timedelta(minutes=window_minutes)
        if now - first_attempt < window:
            if attempts >= max_attempts:
                return False
            login_attempts[identifier] = (attempts + 1, first_attempt)
        else:
            login_attempts[identifier] = (1, now)
    else:
        login_attempts[identifier] = (1, now)
    return True

# ============================================================================
# AUTHENTICATION DECORATORS
# ============================================================================

def login_required(f):
    """Decorator to ensure user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue', 'error')
            return redirect(url_for('login'))
        
        # Check subscription validity
        conn = get_master_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT status, subscription_end_date FROM companies WHERE company_code = %s",
            (session.get('company_code'),)
        )
        company = cursor.fetchone()
        release_db_connection(conn)
        
        if not company or company['status'] != 'ACTIVE':
            session.clear()
            flash('Your subscription has expired. Please contact support.', 'error')
            return redirect(url_for('login'))
        
        if company['subscription_end_date']:
            from datetime import date
            if isinstance(company['subscription_end_date'], str):
                end_date = datetime.strptime(company['subscription_end_date'], '%Y-%m-%d').date()
            else:
                end_date = company['subscription_end_date']
            
            if end_date < date.today():
                session.clear()
                flash('Your subscription has expired. Please contact support.', 'error')
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    """Decorator to ensure user is a super admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'super_admin':
            flash('Access denied. Super admin only.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def developer_required(f):
    """Decorator to ensure developer is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'developer' not in session:
            flash('Developer access required', 'error')
            return redirect(url_for('developer_login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# LEAD SCORING FUNCTION
# ============================================================================

# Status scoring lookup table for O(1) access
STATUS_SCORES = {
    'Closed - Won': 100,
    'Closed - Lost': 0,
    'Not Interested': 0,
    'Not Yet Contacted': 0,
    'Contacted': 10,
    'Interested': 25,
    'Followup': 35,
    'Follow-up': 35,
    'Follow-up Scheduled': 45,
    'Disqualified': -30,
    'On-Hold': -10,
    'Not Responding': 5,
    'Qualified': 40,
    'Registered': 40
}

def _parse_date_safely(date_input):
    """Parse a date or datetime to a date object."""
    if hasattr(date_input, 'date'):
        return date_input.date()
    return datetime.strptime(str(date_input)[:10], '%Y-%m-%d').date()

def _get_category_from_score(score):
    """Fast category lookup"""
    if score >= 70:
        return 'Hot'
    elif score >= 40:
        return 'Warm'
    return 'Cold'

def calculate_lead_score(lead_id, company_id):
    """
    Calculate lead score dynamically based on multiple factors
    Returns: (score, category)
    
    Scoring Algorithm:
    - Status-based: 0-45 points (progress indicator)
    - Registration: 20-40 points (financial commitment)
    - Documents: 5 points each (engagement)
    - Interactions: 3 points each (touchpoints)
    - Details: 5 points each (completeness)
    - Inactivity: -5 to -35 penalty (staleness)
    
    Note: This function only calculates and returns values, does NOT update database
    """
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    
    # Get lead details with all related data in one query
    cursor.execute("""
        SELECT l.*, 
               COALESCE(d.doc_count, 0) as doc_count,
               COALESCE(i.interaction_count, 0) as interaction_count,
               i.last_interaction
        FROM leads l
        LEFT JOIN (
            SELECT lead_id, COUNT(*) as doc_count 
            FROM documents WHERE company_id = %s AND lead_id = %s GROUP BY lead_id
        ) d ON l.id = d.lead_id
        LEFT JOIN (
            SELECT lead_id, COUNT(*) as interaction_count, MAX(created_at) as last_interaction
            FROM interactions WHERE company_id = %s AND lead_id = %s GROUP BY lead_id
        ) i ON l.id = i.lead_id
        WHERE l.company_id = %s AND l.id = %s
    """, (company_id, lead_id, company_id, lead_id, company_id, lead_id))
    lead = cursor.fetchone()
    
    if not lead:
        release_db_connection(conn)
        return 0, 'Cold'
    
    # Fast status lookup with early returns
    status = lead['lead_status']
    if status in ('Closed - Won', 'Closed - Lost', 'Not Interested'):
        release_db_connection(conn)
        return STATUS_SCORES[status], ('Hot' if status == 'Closed - Won' else 'Cold')
    
    score = STATUS_SCORES.get(status, 0)
    
    # Registration amount scoring with optimized logic
    registration_amount = lead['registration_amount'] or 0
    if registration_amount >= 50000:
        score += 40
    elif registration_amount >= 20000:
        score += 35
    elif registration_amount >= 10000:
        score += 30
    elif registration_amount >= 5000:
        score += 25
    elif registration_amount > 0:
        score += 20
    
    # Engagement indicators - already fetched from JOIN
    doc_count = lead['doc_count']
    interaction_count = lead['interaction_count']
    score += doc_count * 5 + interaction_count * 3
    
    # Lead details completeness
    if lead['country_preference']:
        score += 5
    if lead['course_level']:
        score += 5
    
    # Inactivity penalty with cached date parsing
    last_interaction = lead['last_interaction']
    today = date.today()
    
    if last_interaction:
        days_inactive = (today - _parse_date_safely(last_interaction)).days
    elif lead['lead_received_date']:
        days_inactive = (today - _parse_date_safely(lead['lead_received_date'])).days
    else:
        days_inactive = 0
    
    # Apply penalties with optimized logic
    if days_inactive > 30:
        score -= 20
    elif days_inactive > 14:
        score -= 10
        if doc_count == 0:
            score -= 15
    elif days_inactive > 7:
        score -= 5
    
    release_db_connection(conn)
    
    # Boundary check and categorization
    score = max(0, min(100, score))
    category = _get_category_from_score(score)
    
    return score, category

def update_lead_score(lead_id, company_id, score=None, category=None):
    """
    Update lead score in database
    If score/category not provided, will calculate them
    """
    if score is None or category is None:
        score, category = calculate_lead_score(lead_id, company_id)
    
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE leads 
        SET score = %s, score_category = %s, score_updated_at = CURRENT_TIMESTAMP 
        WHERE id = %s AND company_id = %s
    """, (score, category, lead_id, company_id))
    
    conn.commit()
    release_db_connection(conn)
    
    return score, category

def get_lead_score(lead_id, company_id):
    """
    Get lead score from database, calculate if not available
    Returns: (score, category)
    """
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT score, score_category 
        FROM leads 
        WHERE id = %s AND company_id = %s
    """, (lead_id, company_id))
    
    result = cursor.fetchone()
    release_db_connection(conn)
    
    if result and result['score'] is not None:
        return result['score'], result['score_category']
    else:
        # Calculate and store if not available
        return update_lead_score(lead_id, company_id)

def update_lead_scores_bulk(lead_ids, company_id, scores_dict):
    """
    Bulk update lead scores in database
    scores_dict: {lead_id: (score, category)}
    """
    if not lead_ids or not scores_dict:
        return
    
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    
    # Prepare bulk update data
    update_data = []
    for lead_id in lead_ids:
        if lead_id in scores_dict:
            score, category = scores_dict[lead_id]
            update_data.append((score, category, lead_id, company_id))
    
    # Execute bulk update
    cursor.executemany("""
        UPDATE leads 
        SET score = %s, score_category = %s, score_updated_at = CURRENT_TIMESTAMP 
        WHERE id = %s AND company_id = %s
    """, update_data)
    
    conn.commit()
    release_db_connection(conn)

def calculate_lead_scores_bulk(lead_ids, company_id=None, user_id=None):
    """
    Bulk scoring helper to avoid N+1 queries in list/report views.
    Returns a mapping: {lead_id: (score, category)}.
    """
    if not lead_ids:
        return {}

    lead_ids = list({int(lid) for lid in lead_ids})

    if company_id is None:
        company_id = session.get('company_id')
    
    conn = get_company_db(company_id)
    cursor = conn.cursor()

    # Single comprehensive query to get all data at once
    # Add user filtering if user_id is provided
    user_filter_sql = ""
    query_params = [company_id, lead_ids, company_id, lead_ids, company_id, lead_ids]
    
    if user_id:
        user_filter_sql = "AND l.assigned_user_id = %s"
        query_params.append(user_id)
    
    cursor.execute(f"""
        SELECT l.*, 
               COALESCE(d.doc_count, 0) as doc_count,
               COALESCE(i.interaction_count, 0) as interaction_count,
               i.last_interaction
        FROM leads l
        LEFT JOIN (
            SELECT lead_id, COUNT(*) as doc_count 
            FROM documents WHERE company_id = %s AND lead_id = ANY(%s) 
            GROUP BY lead_id
        ) d ON l.id = d.lead_id
        LEFT JOIN (
            SELECT lead_id, COUNT(*) as interaction_count, MAX(created_at) as last_interaction
            FROM interactions WHERE company_id = %s AND lead_id = ANY(%s)
            GROUP BY lead_id
        ) i ON l.id = i.lead_id
        WHERE l.company_id = %s AND l.id = ANY(%s) {user_filter_sql}
    """, query_params)
    
    leads_data = cursor.fetchall()
    
    if not leads_data:
        release_db_connection(conn)
        return {}

    today = date.today()
    scores = {}

    # Process all leads in a single loop with optimized logic
    for lead in leads_data:
        lid = lead['id']
        status = lead['lead_status']
        
        # Fast status lookup with early returns
        if status in ('Closed - Won', 'Closed - Lost', 'Not Interested'):
            scores[lid] = (STATUS_SCORES[status], ('Hot' if status == 'Closed - Won' else 'Cold'))
            continue
        
        score = STATUS_SCORES.get(status, 0)
        
        # Registration amount scoring
        registration_amount = lead.get('registration_amount') or 0
        if registration_amount >= 50000:
            score += 40
        elif registration_amount >= 20000:
            score += 35
        elif registration_amount >= 10000:
            score += 30
        elif registration_amount >= 5000:
            score += 25
        elif registration_amount > 0:
            score += 20

        # Engagement indicators
        doc_count = lead['doc_count']
        interaction_count = lead['interaction_count']
        score += doc_count * 5 + interaction_count * 3

        # Lead details completeness
        if lead.get('country_preference'):
            score += 5
        if lead.get('course_level'):
            score += 5

        # Inactivity penalty with cached date parsing
        last_interaction = lead['last_interaction']
        if last_interaction:
            days_inactive = (today - _parse_date_safely(last_interaction)).days
        elif lead.get('lead_received_date'):
            days_inactive = (today - _parse_date_safely(lead['lead_received_date'])).days
        else:
            days_inactive = 0

        # Apply penalties
        if days_inactive > 30:
            score -= 20
        elif days_inactive > 14:
            score -= 10
            if doc_count == 0:
                score -= 15
        elif days_inactive > 7:
            score -= 5

        # Boundary check and categorization
        score = max(0, min(100, score))
        category = _get_category_from_score(score)
        scores[lid] = (score, category)

    release_db_connection(conn)
    return scores

# ============================================================================
# TIER 1-D: NEXT BEST ACTION ENGINE
# ============================================================================

# Outcome → recommended next action mapping
_NBA_OUTCOME_ACTIONS = {
    'Price Objection': ('💡 Address fee concern', 'Share scholarship/loan options or a fee breakdown to overcome the price objection.'),
    'Visa Concern':    ('🛂 Address visa concern', 'Provide visa success rate data and schedule a dedicated visa Q&A call.'),
    'Ghost':           ('👻 Re-engage ghost lead', 'Try a different channel (WhatsApp if not tried, or a call if only messaged). Leads often respond to a change of medium.'),
    'Requested Docs':  ('📄 Follow up on documents', "Check if the student has gathered the requested documents. Offer to help if they're stuck."),
    'Committed':       ('🎉 Formalise commitment', 'Move to Registered status and collect registration amount. Strike while the iron is hot!'),
    'Interested':      ('🔥 Strike while hot', 'Student showed interest — send course details, fee structure, and a shortlist of universities today.'),
    'Needs Follow-up': ('📞 Schedule your next contact', "Log a follow-up date now so this lead doesn't slip through the cracks."),
}

def get_next_best_action(lead, interactions, followups):
    """
    Determine the Next Best Action for a lead based on current state.
    Returns a dict with: priority ('critical'|'warning'|'info'), title, message
    or None if no action needed.
    """
    today = date.today()
    status = lead.get('lead_status', '')
    country = lead.get('country_preference', '')
    days_since_received = 0

    if lead.get('lead_received_date'):
        received = _parse_date_safely(lead['lead_received_date'])
        days_since_received = (today - received).days

    # Days since last interaction
    days_since_interaction = None
    if interactions:
        last_dt = interactions[0].get('contact_date')
        if last_dt:
            last_date = _parse_date_safely(last_dt)
            days_since_interaction = (today - last_date).days

    # Pending follow-ups
    has_overdue_followup = any(
        not f.get('completed') and _parse_date_safely(f['followup_date']) < today
        for f in followups
    )

    # Rule 1: Never contacted leads older than 1 day — CRITICAL
    if status == 'Not Yet Contacted' and days_since_received >= 1:
        return {
            'priority': 'critical',
            'icon': '🚨',
            'title': f'Lead untouched for {days_since_received} day{"s" if days_since_received != 1 else ""}!',
            'message': 'Speed is everything — leads contacted within 5 minutes are 9x more likely to convert. Call or WhatsApp this student right now.'
        }

    # Rule 2: Interested lead with no interaction in 3+ days
    if status in ('Interested', 'Follow-up', 'Follow-up Scheduled') and days_since_interaction is not None and days_since_interaction >= 3:
        return {
            'priority': 'critical',
            'icon': '⏰',
            'title': f'No contact in {days_since_interaction} days — risk of going cold!',
            'message': f'This lead showed interest{" in " + country if country else ""}. Reach out now with a course shortlist or intake deadline reminder.'
        }

    # Rule 3: Overdue follow-up
    if has_overdue_followup:
        return {
            'priority': 'warning',
            'icon': '📅',
            'title': 'You have an overdue follow-up for this lead',
            'message': 'Complete it now: mark it done after your call/message, then schedule the next step.'
        }

    # Rule 4: Last interaction outcome drives action
    if interactions:
        last_outcome = interactions[0].get('interaction_outcome', '')
        if last_outcome in _NBA_OUTCOME_ACTIONS:
            title, message = _NBA_OUTCOME_ACTIONS[last_outcome]
            return {
                'priority': 'info',
                'icon': '💬',
                'title': title,
                'message': message
            }

    # Rule 5: Stale active lead (no interaction in 7+ days)
    if status not in ('Closed - Won', 'Closed - Lost', 'Not Interested', 'Disqualified') and days_since_interaction is not None and days_since_interaction >= 7:
        return {
            'priority': 'warning',
            'icon': '🕰️',
            'title': f'Lead has been inactive for {days_since_interaction} days',
            'message': 'Re-engage before this lead goes cold permanently. Try a new angle — upcoming intake deadline, new scholarship, or a quick check-in.'
        }

    # Rule 6: No follow-up scheduled for active leads
    active_statuses = ('Contacted', 'Interested', 'Follow-up', 'Qualified')
    pending_followups = [f for f in followups if not f.get('completed')]
    if status in active_statuses and not pending_followups:
        return {
            'priority': 'info',
            'icon': '📌',
            'title': 'No follow-up scheduled',
            'message': 'Always leave every lead with a next step. Schedule a follow-up date below to keep momentum going.'
        }

    return None

# Register NBA function as Jinja2 global so templates can call it directly
app.jinja_env.globals['get_next_best_action'] = get_next_best_action

# ============================================================================
# TIER 2-G: PIPELINE REVENUE HELPER
# ============================================================================

# Default stage probabilities (used if company hasn't customised)
DEFAULT_STAGE_PROBABILITIES = {
    'Not Yet Contacted':  5,
    'Contacted':         10,
    'Interested':        20,
    'Follow-up':         30,
    'Follow-up Scheduled': 35,
    'On-Hold':           15,
    'Qualified':         40,
    'Registered':        70,
    'Closed - Won':     100,
    'Closed - Lost':      0,
    'Not Interested':     0,
    'Disqualified':       0,
    'Not Responding':     5,
}

def get_pipeline_probabilities(company_id):
    """
    Return stage→probability dict for a company.
    Falls back to defaults for any stage not customised.
    """
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT stage, probability FROM pipeline_stage_probabilities WHERE company_id = %s",
            (company_id,)
        )
        rows = cursor.fetchall()
        probs = dict(DEFAULT_STAGE_PROBABILITIES)
        for row in rows:
            probs[row['stage']] = row['probability']
        return probs
    except Exception:
        return dict(DEFAULT_STAGE_PROBABILITIES)
    finally:
        release_db_connection(conn)

def get_weighted_pipeline_value(company_id, user_id=None):
    """
    Calculate weighted pipeline value: sum of (lead_value * stage_probability / 100)
    for all active (non-closed) leads.
    Returns dict: expected_revenue, total_pipeline_value, stage_breakdown
    """
    probs = get_pipeline_probabilities(company_id)
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    try:
        base_query = """
            SELECT lead_status, 
                   COALESCE(lead_value, 0) as lead_value,
                   COALESCE(registration_amount, 0) as registration_amount
            FROM leads
            WHERE company_id = %s
              AND lead_status NOT IN ('Closed - Won', 'Closed - Lost', 'Not Interested', 'Disqualified')
        """
        params = [company_id]
        if user_id:
            base_query += " AND assigned_user_id = %s"
            params.append(user_id)
        cursor.execute(base_query, params)
        leads = cursor.fetchall()

        expected_revenue = 0.0
        total_pipeline_value = 0.0
        stage_breakdown = {}

        for lead in leads:
            stage = lead['lead_status']
            value = float(lead['lead_value']) if lead['lead_value'] else 0.0
            prob = probs.get(stage, 10) / 100.0
            weighted = value * prob
            expected_revenue += weighted
            total_pipeline_value += value
            if stage not in stage_breakdown:
                stage_breakdown[stage] = {'count': 0, 'value': 0.0, 'weighted': 0.0, 'probability': probs.get(stage, 10)}
            stage_breakdown[stage]['count'] += 1
            stage_breakdown[stage]['value'] += value
            stage_breakdown[stage]['weighted'] += weighted

        # Also add won leads revenue (100% probability)
        cursor.execute("""
            SELECT COALESCE(SUM(registration_amount), 0) as won_revenue
            FROM leads WHERE company_id = %s AND lead_status = 'Closed - Won'
        """ + (" AND assigned_user_id = %s" if user_id else ""),
            [company_id] + ([user_id] if user_id else [])
        )
        won_row = cursor.fetchone()
        won_revenue = float(won_row['won_revenue']) if won_row else 0.0

        return {
            'expected_revenue': round(expected_revenue, 2),
            'total_pipeline_value': round(total_pipeline_value, 2),
            'won_revenue': round(won_revenue, 2),
            'stage_breakdown': stage_breakdown,
        }
    except Exception:
        return {'expected_revenue': 0, 'total_pipeline_value': 0, 'won_revenue': 0, 'stage_breakdown': {}}
    finally:
        release_db_connection(conn)

# ============================================================================
# TIER 2-F: OVERDUE FOLLOW-UP ESCALATION HELPER
# ============================================================================

def escalate_overdue_followups(company_id):
    """
    Mark follow-ups overdue by > 1 day as escalated.
    Called on dashboard load so managers always see fresh escalations.
    Safe to call multiple times (idempotent).
    Also fires a notification to all super_admins for newly escalated items.
    """
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    try:
        # Fetch newly-to-be-escalated items so we can notify admins
        cursor.execute("""
            SELECT f.id, f.lead_id, l.name as lead_name, u.name as counsellor_name
            FROM followups f
            JOIN leads l ON f.lead_id = l.id
            LEFT JOIN users u ON l.assigned_user_id = u.id
            WHERE f.company_id = %s
              AND f.completed = FALSE
              AND f.followup_escalated = FALSE
              AND f.followup_date < CURRENT_DATE - INTERVAL '1 day'
        """, (company_id,))
        newly_escalated = cursor.fetchall()

        cursor.execute("""
            UPDATE followups
            SET followup_escalated = TRUE, escalated_at = CURRENT_TIMESTAMP
            WHERE company_id = %s
              AND completed = FALSE
              AND followup_escalated = FALSE
              AND followup_date < CURRENT_DATE - INTERVAL '1 day'
        """, (company_id,))
        conn.commit()

        # ── TIER 4: Notify admins for each newly escalated follow-up ─────────
        for item in newly_escalated:
            create_notification_for_admins(
                company_id, 'followup_overdue',
                f'⚠️ Overdue follow-up: {item["lead_name"]}',
                f'Follow-up for {item["lead_name"]} (assigned to {item["counsellor_name"] or "unknown"}) is overdue by more than 1 day.',
                lead_id=item['lead_id']
            )
    except Exception:
        pass
    finally:
        release_db_connection(conn)

# ============================================================================
# GLOBAL ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def page_not_found(e):
    """404 — page not found"""
    return render_template('error.html',
                           error_code=404,
                           error_title='Page Not Found',
                           error_message='The page you were looking for does not exist.'), 404

@app.errorhandler(403)
def forbidden(e):
    """403 — forbidden"""
    return render_template('error.html',
                           error_code=403,
                           error_title='Access Denied',
                           error_message='You do not have permission to access this page.'), 403

@app.errorhandler(500)
def internal_server_error(e):
    """500 — unhandled server error"""
    # Log the real error so you can still see it in server logs / Render logs
    app.logger.exception('Unhandled server error: %s', e)
    return render_template('error.html',
                           error_code=500,
                           error_title='Something Went Wrong',
                           error_message=None), 500

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    """Catch-all for any unhandled Python exception (e.g. psycopg2 errors)"""
    app.logger.exception('Unexpected exception: %s', e)
    return render_template('error.html',
                           error_code=500,
                           error_title='Something Went Wrong',
                           error_message=None), 500


# ============================================================================
# LANDING PAGE & PUBLIC ROUTES
# ============================================================================

@app.route('/')
def landing():
    """Landing page with Sign Up and Login buttons"""
    return render_template('landing.html')

@app.route('/pricing')
def pricing():
    """Pricing page — publicly accessible ONLY via landing page link, hidden from logged-in nav"""
    return render_template('pricing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Company registration page - ONLY ONE COMPANY ALLOWED"""
    # Signup is open — any company can register (pending developer approval)
    if request.method == 'POST':
        company_name = request.form.get('company_name', '').strip()
        company_code = request.form.get('company_code', '').strip().lower()
        super_admin_name = request.form.get('super_admin_name', '').strip()
        super_admin_email = request.form.get('super_admin_email', '').strip().lower()
        super_admin_password = request.form.get('super_admin_password', '')
        
        # Validation
        if not all([company_name, company_code, super_admin_name, super_admin_email, super_admin_password]):
            flash('All fields are required', 'error')
            return render_template('signup.html')
        
        conn = get_master_db()
        cursor = conn.cursor()

        # Check for duplicate company name
        cursor.execute("SELECT id FROM companies WHERE LOWER(company_name) = LOWER(%s)", (company_name,))
        if cursor.fetchone():
            release_db_connection(conn)
            flash('Company with same name exists', 'error')
            return render_template('signup.html')

        # Check for duplicate company code
        cursor.execute("SELECT id FROM companies WHERE company_code = %s", (company_code,))
        if cursor.fetchone():
            release_db_connection(conn)
            flash('Company code already in use. Please choose a different code.', 'error')
            return render_template('signup.html')
        
        # Create company record and get ID
        cursor.execute(
            """INSERT INTO companies (company_name, company_code, status) 
               VALUES (%s, %s, 'PENDING') RETURNING id""",
            (company_name, company_code)
        )
        company_id = cursor.fetchone()['id']
        conn.commit()
        release_db_connection(conn)
        
        # Create company database tables
        init_company_db(company_code)
        
        # Create super admin user with company_id
        company_conn = get_company_db(company_code)
        company_cursor = company_conn.cursor()
        
        company_cursor.execute(
            """INSERT INTO users (company_id, name, email, password_hash, role) 
               VALUES (%s, %s, %s, %s, 'super_admin')""",
            (company_id, super_admin_name, super_admin_email, generate_password_hash(super_admin_password))
        )
        
        company_conn.commit()
        release_db_connection(company_conn)
        
        flash('Registration successful! Your account is pending developer approval. You will be able to login once approved.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Company user login"""
    if request.method == 'POST':
        company_code = request.form.get('company_code', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Rate limit by compound key — isolates brute-force per tenant
        rate_key = f"{company_code}:{email}"
        if not check_rate_limit(rate_key):
            flash('Too many login attempts. Please wait 15 minutes before trying again.', 'error')
            return render_template('login.html')
        
        conn = get_master_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, status, subscription_end_date FROM companies WHERE company_code = %s",
            (company_code,)
        )
        company = cursor.fetchone()
        
        if not company:
            release_db_connection(conn)
            flash('Invalid company code or credentials', 'error')
            return render_template('login.html')
        
        company_id = company['id']
        
        if company['status'] != 'ACTIVE':
            release_db_connection(conn)
            flash('Your company account is not active. Please contact support.', 'error')
            return render_template('login.html')
        
        if company['subscription_end_date']:
            end_date = company['subscription_end_date']
            if isinstance(end_date, str):
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            elif hasattr(end_date, 'date'):
                end_date = end_date.date()
            if date.today() > end_date:
                release_db_connection(conn)
                flash('Your subscription has expired. Please contact support.', 'error')
                return render_template('login.html')
        
        release_db_connection(conn)
        
        company_conn = get_company_db(company_code)
        company_cursor = company_conn.cursor()
        company_cursor.execute(
            "SELECT * FROM users WHERE company_id = %s AND email = %s",
            (company_id, email)
        )
        user = company_cursor.fetchone()
        release_db_connection(company_conn)
        
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Invalid company code or credentials', 'error')
            return render_template('login.html')
        
        session.clear()
        
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        session['user_email'] = user['email']
        session['role'] = user['role']
        session['company_code'] = company_code
        session['company_id'] = company_id
        session['login_type'] = 'company_user'
        
        flash(f'Welcome, {user["name"]}!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout current user"""
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('landing'))

# ============================================================================
# DEVELOPER ROUTES
# ============================================================================

@app.route('/developer/login', methods=['GET', 'POST'])
def developer_login():
    """Developer login page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        conn = get_master_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM developer_admin WHERE username = %s", (username,))
        admin = cursor.fetchone()
        release_db_connection(conn)
        
        if admin and check_password_hash(admin['password_hash'], password):
            session.clear()
            
            session['developer'] = True
            session['developer_id'] = admin['id']
            session['login_type'] = 'developer'
            flash('Developer login successful', 'success')
            return redirect(url_for('developer_dashboard'))
        
        flash('Invalid credentials', 'error')
    
    return render_template('developer_login.html')

@app.route('/developer/logout')
def developer_logout():
    """Developer logout"""
    session.pop('developer', None)
    session.pop('developer_id', None)
    flash('Developer logged out', 'success')
    return redirect(url_for('developer_login'))

@app.route('/developer/dashboard')
@developer_required
def developer_dashboard():
    """Developer dashboard showing all companies"""
    conn = get_master_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM companies ORDER BY created_at DESC")
    companies = cursor.fetchall()
    release_db_connection(conn)
    
    return render_template('developer_dashboard.html', companies=companies)

@app.route('/developer/change-password', methods=['GET', 'POST'])
@developer_required
def developer_change_password():
    """Developer change password page"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('developer_change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('developer_change_password.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('developer_change_password.html')
        
        conn = get_master_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM developer_admin WHERE id = %s", (session['developer_id'],))
        admin = cursor.fetchone()
        
        if not admin or not check_password_hash(admin['password_hash'], current_password):
            release_db_connection(conn)
            flash('Current password is incorrect', 'error')
            return render_template('developer_change_password.html')
        
        cursor.execute(
            "UPDATE developer_admin SET password_hash = %s WHERE id = %s",
            (generate_password_hash(new_password), session['developer_id'])
        )
        conn.commit()
        release_db_connection(conn)
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('developer_dashboard'))
    
    return render_template('developer_change_password.html')

@app.route('/developer/approve/<int:company_id>', methods=['POST'])
@developer_required
def approve_company(company_id):
    """Approve a company and set subscription dates"""
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    if not start_date or not end_date:
        flash('Start and end dates are required', 'error')
        return redirect(url_for('developer_dashboard'))
    
    conn = get_master_db()
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE companies 
           SET status = 'ACTIVE', subscription_start_date = %s, subscription_end_date = %s
           WHERE id = %s""",
        (start_date, end_date, company_id)
    )
    conn.commit()
    release_db_connection(conn)
    
    flash('Company approved successfully', 'success')
    return redirect(url_for('developer_dashboard'))

@app.route('/developer/suspend/<int:company_id>', methods=['POST'])
@developer_required
def suspend_company(company_id):
    """Suspend a company"""
    conn = get_master_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE companies SET status = 'SUSPENDED' WHERE id = %s", (company_id,))
    conn.commit()
    release_db_connection(conn)
    
    flash('Company suspended', 'success')
    return redirect(url_for('developer_dashboard'))

@app.route('/developer/activate/<int:company_id>', methods=['POST'])
@developer_required
def activate_company(company_id):
    """Reactivate a suspended company"""
    conn = get_master_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE companies SET status = 'ACTIVE' WHERE id = %s", (company_id,))
    conn.commit()
    release_db_connection(conn)
    
    flash('Company activated', 'success')
    return redirect(url_for('developer_dashboard'))

@app.route('/developer/extend/<int:company_id>', methods=['POST'])
@developer_required
def extend_subscription(company_id):
    """Extend company subscription"""
    new_end_date = request.form.get('end_date')
    
    if not new_end_date:
        flash('End date is required', 'error')
        return redirect(url_for('developer_dashboard'))
    
    conn = get_master_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE companies SET subscription_end_date = %s WHERE id = %s",
        (new_end_date, company_id)
    )
    conn.commit()
    release_db_connection(conn)
    
    flash('Subscription extended', 'success')
    return redirect(url_for('developer_dashboard'))

# ============================================================================
# SUPER ADMIN — CHANGE OWN PASSWORD
# ============================================================================

@app.route('/account/change-password', methods=['GET', 'POST'])
@login_required
@super_admin_required
def change_password():
    """Allow a super admin to change their own password"""
    if request.method == 'POST':
        current_password  = request.form.get('current_password', '')
        new_password      = request.form.get('new_password', '')
        confirm_password  = request.form.get('confirm_password', '')

        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required.', 'error')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('New password and confirmation do not match.', 'error')
            return render_template('change_password.html')

        if len(new_password) < 8:
            flash('New password must be at least 8 characters.', 'error')
            return render_template('change_password.html')

        conn = get_company_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password_hash FROM users WHERE id = %s AND company_id = %s",
            (session['user_id'], session['company_id'])
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password_hash'], current_password):
            release_db_connection(conn)
            flash('Current password is incorrect.', 'error')
            return render_template('change_password.html')

        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s AND company_id = %s",
            (generate_password_hash(new_password), session['user_id'], session['company_id'])
        )
        conn.commit()
        release_db_connection(conn)

        flash('Password changed successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')


# ── Developer: reset a company super admin's password ───────────────────────

@app.route('/developer/reset-password/<int:company_id>', methods=['GET', 'POST'])
@developer_required
def developer_reset_password(company_id):
    """Developer resets the super admin password for a given company"""
    # Fetch company info
    conn = get_master_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, company_name, company_code FROM companies WHERE id = %s", (company_id,))
    company = cursor.fetchone()
    release_db_connection(conn)

    if not company:
        flash('Company not found.', 'error')
        return redirect(url_for('developer_dashboard'))

    if request.method == 'POST':
        new_password     = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not new_password or not confirm_password:
            flash('Both password fields are required.', 'error')
            return render_template('developer_reset_password.html', company=company)

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('developer_reset_password.html', company=company)

        if len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('developer_reset_password.html', company=company)

        # Update the super_admin user's password in the shared users table
        conn = get_company_db(company_id)
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE users SET password_hash = %s
               WHERE company_id = %s AND role = 'super_admin'""",
            (generate_password_hash(new_password), company_id)
        )
        updated = cursor.rowcount
        conn.commit()
        release_db_connection(conn)

        if updated == 0:
            flash('No super admin user found for this company.', 'error')
        else:
            flash(f'Password for {company["company_name"]} super admin reset successfully.', 'success')

        return redirect(url_for('developer_dashboard'))

    return render_template('developer_reset_password.html', company=company)


# ============================================================================
# SUPER ADMIN — FORGOT PASSWORD (self-service via developer-generated token)
# ============================================================================

# In-memory token store: {token: {'company_id': int, 'expires': datetime}}
_password_reset_tokens = {}

@app.route('/developer/generate-reset-token/<int:company_id>', methods=['POST'])
@developer_required
def developer_generate_reset_token(company_id):
    """Developer generates a one-time password reset token for a company's super admin."""
    conn = get_master_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, company_name FROM companies WHERE id = %s", (company_id,))
    company = cursor.fetchone()
    release_db_connection(conn)

    if not company:
        flash('Company not found.', 'error')
        return redirect(url_for('developer_dashboard'))

    token = secrets.token_urlsafe(32)
    _password_reset_tokens[token] = {
        'company_id': company_id,
        'expires': datetime.now() + timedelta(hours=1)
    }

    reset_url = url_for('super_admin_reset_password', token=token, _external=True)
    flash(
        f'Reset link for {company["company_name"]} (valid 1 hour): {reset_url}',
        'success'
    )
    return redirect(url_for('developer_dashboard'))


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def super_admin_reset_password(token):
    """Super admin uses a developer-provided token to set a new password."""
    token_data = _password_reset_tokens.get(token)

    if not token_data or datetime.now() > token_data['expires']:
        flash('This password reset link is invalid or has expired. Please ask your developer for a new link.', 'error')
        return redirect(url_for('login'))

    company_id = token_data['company_id']

    # Fetch company name for display
    conn = get_master_db()
    cursor = conn.cursor()
    cursor.execute("SELECT company_name FROM companies WHERE id = %s", (company_id,))
    company = cursor.fetchone()
    release_db_connection(conn)

    if request.method == 'POST':
        new_password     = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not new_password or not confirm_password:
            flash('Both fields are required.', 'error')
            return render_template('super_admin_reset_password.html', token=token, company=company)

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('super_admin_reset_password.html', token=token, company=company)

        if len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('super_admin_reset_password.html', token=token, company=company)

        conn = get_company_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE company_id = %s AND role = 'super_admin'",
            (generate_password_hash(new_password), company_id)
        )
        updated = cursor.rowcount
        conn.commit()
        release_db_connection(conn)

        # Invalidate token after use
        _password_reset_tokens.pop(token, None)

        if updated == 0:
            flash('No super admin account found for this company.', 'error')
        else:
            flash('Password reset successfully! You can now log in with your new password.', 'success')

        return redirect(url_for('login'))

    return render_template('super_admin_reset_password.html', token=token, company=company)


# ============================================================================
# COMPANY DASHBOARD
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard for company users"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Get pending follow-ups for current user
    if session['role'] == 'super_admin':
        cursor.execute("""
            SELECT f.*, l.name as lead_name, l.phone, u.name as assigned_user_name
            FROM followups f
            JOIN leads l ON f.lead_id = l.id
            LEFT JOIN users u ON l.assigned_user_id = u.id
            WHERE f.company_id = %s AND f.completed = FALSE AND f.followup_date <= CURRENT_DATE
            ORDER BY f.followup_date
        """, (session['company_id'],))
    else:
        cursor.execute("""
            SELECT f.*, l.name as lead_name, l.phone 
            FROM followups f
            JOIN leads l ON f.lead_id = l.id
            WHERE f.company_id = %s AND f.user_id = %s AND f.completed = FALSE AND f.followup_date <= CURRENT_DATE
            ORDER BY f.followup_date
        """, (session['company_id'], session['user_id']))
    
    followups = cursor.fetchall()
    
    # Get statistics
    if session['role'] == 'super_admin':
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE company_id = %s", (session['company_id'],))
        total_leads = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE company_id = %s AND lead_status != 'Not Yet Contacted'", (session['company_id'],))
        contacted_leads = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE company_id = %s AND role = 'user'", (session['company_id'],))
        total_users = cursor.fetchone()['count']

        # ── TIER 1-A: DANGER ZONE — Leads not yet contacted > 2 hours ──────────
        cursor.execute("""
            SELECT l.id, l.name, l.phone, l.whatsapp, l.lead_source, l.country_preference,
                   l.lead_received_date, u.name as assigned_user_name,
                   EXTRACT(EPOCH FROM (NOW() - l.lead_received_date))/3600 as hours_waiting
            FROM leads l
            LEFT JOIN users u ON l.assigned_user_id = u.id
            WHERE l.company_id = %s
              AND l.lead_status = 'Not Yet Contacted'
              AND l.lead_received_date <= NOW() - INTERVAL '2 hours'
            ORDER BY l.lead_received_date ASC
            LIMIT 20
        """, (session['company_id'],))
        danger_zone_leads = cursor.fetchall()

        # ── TIER 1-A: Avg time to first contact (last 30 days) ─────────────────
        cursor.execute("""
            SELECT AVG(EXTRACT(EPOCH FROM (first_contacted_at - lead_received_date))/3600) as avg_hours
            FROM leads
            WHERE company_id = %s
              AND first_contacted_at IS NOT NULL
              AND lead_received_date >= NOW() - INTERVAL '30 days'
        """, (session['company_id'],))
        avg_row = cursor.fetchone()
        avg_contact_hours = round(avg_row['avg_hours'], 1) if avg_row and avg_row['avg_hours'] else None

        # ── TIER 1-C: Leads closed without a reason captured ───────────────────
        cursor.execute("""
            SELECT COUNT(*) as count FROM leads
            WHERE company_id = %s
              AND lead_status IN ('Closed - Lost', 'Not Interested', 'Disqualified')
              AND closed_reason IS NULL
        """, (session['company_id'],))
        missing_reasons = cursor.fetchone()['count']

        # ── TIER 2-F: Escalated overdue follow-ups for super_admin ─────────────
        cursor.execute("""
            SELECT f.id, f.followup_date, f.note, f.escalated_at, f.escalation_acknowledged,
                   l.id as lead_id, l.name as lead_name, l.phone,
                   u.name as assigned_user_name
            FROM followups f
            JOIN leads l ON f.lead_id = l.id
            LEFT JOIN users u ON l.assigned_user_id = u.id
            WHERE f.company_id = %s
              AND f.completed = FALSE
              AND f.followup_escalated = TRUE
              AND f.escalation_acknowledged = FALSE
            ORDER BY f.followup_date ASC
            LIMIT 15
        """, (session['company_id'],))
        escalated_followups = cursor.fetchall()

        # ── TIER 2-G: Pipeline revenue widget ──────────────────────────────────
        pipeline_data = get_weighted_pipeline_value(session['company_id'])

    else:
        cursor.execute("SELECT COUNT(*) as count FROM leads WHERE company_id = %s AND assigned_user_id = %s", (session['company_id'], session['user_id'],))
        total_leads = cursor.fetchone()['count']
        
        cursor.execute(
            "SELECT COUNT(*) as count FROM leads WHERE company_id = %s AND assigned_user_id = %s AND lead_status != 'Not Yet Contacted'",
            (session['company_id'], session['user_id'],)
        )
        contacted_leads = cursor.fetchone()['count']
        
        total_users = 0

        # ── TIER 1-A: Counsellor's own uncontacted leads (> 2 hours) ───────────
        cursor.execute("""
            SELECT l.id, l.name, l.phone, l.whatsapp, l.lead_source, l.country_preference,
                   l.lead_received_date,
                   EXTRACT(EPOCH FROM (NOW() - l.lead_received_date))/3600 as hours_waiting
            FROM leads l
            WHERE l.company_id = %s
              AND l.assigned_user_id = %s
              AND l.lead_status = 'Not Yet Contacted'
              AND l.lead_received_date <= NOW() - INTERVAL '2 hours'
            ORDER BY l.lead_received_date ASC
            LIMIT 10
        """, (session['company_id'], session['user_id']))
        danger_zone_leads = cursor.fetchall()
        avg_contact_hours = None
        missing_reasons = 0
        escalated_followups = []

        # ── TIER 2-G: Pipeline value for counsellor ────────────────────────────
        pipeline_data = get_weighted_pipeline_value(session['company_id'], user_id=session['user_id'])

    release_db_connection(conn)

    # ── TIER 2-F: Auto-escalate overdue follow-ups (idempotent) ────────────────
    escalate_overdue_followups(session['company_id'])

    return render_template('dashboard.html', 
                         followups=followups,
                         total_leads=total_leads,
                         contacted_leads=contacted_leads,
                         total_users=total_users,
                         danger_zone_leads=danger_zone_leads,
                         avg_contact_hours=avg_contact_hours,
                         missing_reasons=missing_reasons,
                         escalated_followups=escalated_followups,
                         pipeline_data=pipeline_data)

# ============================================================================
# USER MANAGEMENT (SUPER ADMIN ONLY)
# ============================================================================

@app.route('/users')
@login_required
@super_admin_required
def users_list():
    """List all users in the company"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE company_id = %s ORDER BY created_at DESC", (session['company_id'],))
    users = cursor.fetchall()
    release_db_connection(conn)
    
    return render_template('users_list.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@super_admin_required
def add_user():
    """Add new user"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role', 'user')
        
        if not all([name, email, password]):
            flash('All fields are required', 'error')
            return render_template('add_user.html')
        
        conn = get_company_db(session['company_id'])
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM users WHERE company_id = %s AND email = %s", (session['company_id'], email))
        if cursor.fetchone():
            release_db_connection(conn)
            flash('Email already exists', 'error')
            return render_template('add_user.html')
        
        cursor.execute(
            "INSERT INTO users (company_id, name, email, password_hash, role) VALUES (%s, %s, %s, %s, %s)",
            (session['company_id'], name, email, generate_password_hash(password), role)
        )
        conn.commit()
        release_db_connection(conn)
        
        flash('User created successfully', 'success')
        return redirect(url_for('users_list'))
    
    return render_template('add_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@super_admin_required
def edit_user(user_id):
    """Edit existing user (super admin only)"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = %s AND company_id = %s", (user_id, session['company_id']))
    user = cursor.fetchone()
    
    if not user:
        release_db_connection(conn)
        flash('User not found', 'error')
        return redirect(url_for('users_list'))
    
    if user_id == session['user_id']:
        release_db_connection(conn)
        flash('Cannot edit your own account from here', 'error')
        return redirect(url_for('users_list'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        new_password = request.form.get('new_password', '').strip()
        role = request.form.get('role', 'user')
        status = request.form.get('status', 'active')
        
        if not name or not email:
            flash('Name and email are required', 'error')
            return render_template('edit_user.html', user=user)
        
        cursor.execute("SELECT id FROM users WHERE company_id = %s AND email = %s AND id != %s", (session['company_id'], email, user_id))
        if cursor.fetchone():
            release_db_connection(conn)
            flash('Email already exists', 'error')
            return render_template('edit_user.html', user=user)
        
        if new_password:
            cursor.execute(
                "UPDATE users SET name = %s, email = %s, password_hash = %s, role = %s WHERE id = %s AND company_id = %s",
                (name, email, generate_password_hash(new_password), role, user_id, session['company_id'])
            )
        else:
            cursor.execute(
                "UPDATE users SET name = %s, email = %s, role = %s WHERE id = %s AND company_id = %s",
                (name, email, role, user_id, session['company_id'])
            )
        
        if status == 'suspended':
            pass
        
        cursor.execute(
            "INSERT INTO audit_logs (company_id, user_id, action, ip_address) VALUES (%s, %s, %s, %s)",
            (session['company_id'], session['user_id'], f'Edited user ID {user_id} ({name})', request.remote_addr)
        )
        
        conn.commit()
        release_db_connection(conn)
        
        flash('User updated successfully', 'success')
        return redirect(url_for('users_list'))
    
    release_db_connection(conn)
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_user(user_id):
    """Delete a user (requires password confirmation)"""
    password = request.form.get('password', '')
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id = %s AND company_id = %s", (session['user_id'], session['company_id']))
    admin = cursor.fetchone()
    
    if not check_password_hash(admin['password_hash'], password):
        release_db_connection(conn)
        flash('Incorrect password', 'error')
        return redirect(url_for('users_list'))
    
    if user_id == session['user_id']:
        release_db_connection(conn)
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('users_list'))
    
    cursor.execute("DELETE FROM users WHERE id = %s AND company_id = %s", (user_id, session['company_id']))
    
    cursor.execute(
        "INSERT INTO audit_logs (company_id, user_id, action, ip_address) VALUES (%s, %s, %s, %s)",
        (session['company_id'], session['user_id'], f'Deleted user ID {user_id}', request.remote_addr)
    )
    
    conn.commit()
    release_db_connection(conn)
    
    flash('User deleted successfully', 'success')
    return redirect(url_for('users_list'))

# ============================================================================
# LEAD MANAGEMENT
# ============================================================================

@app.route('/leads')
@login_required
def leads_list():
    """List all leads (filtered by user role)"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    status_filter = request.args.get('status', '')
    category_filter = request.args.get('category', '')
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    if session['role'] == 'super_admin':
        # Build query with filters
        base_query = """
            SELECT l.*, u.name as assigned_user_name 
            FROM leads l
            LEFT JOIN users u ON l.assigned_user_id = u.id
            WHERE l.company_id = %s
        """
        query_params = [session['company_id']]
        filter_conditions = []
        
        if search_query:
            filter_conditions.append("(l.name LIKE %s OR l.email LIKE %s OR l.phone LIKE %s OR l.country_preference LIKE %s OR l.course_type LIKE %s OR l.course_level LIKE %s OR l.location LIKE %s)")
            search_param = f'%{search_query}%'
            query_params.extend([search_param, search_param, search_param, search_param, search_param, search_param, search_param])
        
        if status_filter:
            filter_conditions.append("l.lead_status = %s")
            query_params.append(status_filter)
        
        if category_filter:
            filter_conditions.append("(l.score_category = %s OR (l.score_category IS NULL AND %s = 'Cold'))")
            query_params.extend([category_filter, category_filter])
        
        if filter_conditions:
            base_query += " AND " + " AND ".join(filter_conditions)
        
        query = base_query + " ORDER BY l.created_at DESC LIMIT %s OFFSET %s"
        query_params.extend([per_page, offset])
        
        cursor.execute(query, query_params)
    else:
        # Build query with filters for regular users
        base_query = """
            SELECT l.*, u.name as assigned_user_name 
            FROM leads l
            LEFT JOIN users u ON l.assigned_user_id = u.id
            WHERE l.company_id = %s AND l.assigned_user_id = %s
        """
        query_params = [session['company_id'], session['user_id']]
        filter_conditions = []
        
        if search_query:
            filter_conditions.append("(l.name LIKE %s OR l.email LIKE %s OR l.phone LIKE %s OR l.country_preference LIKE %s OR l.course_type LIKE %s OR l.course_level LIKE %s OR l.location LIKE %s)")
            search_param = f'%{search_query}%'
            query_params.extend([search_param, search_param, search_param, search_param, search_param, search_param, search_param])
        
        if status_filter:
            filter_conditions.append("l.lead_status = %s")
            query_params.append(status_filter)
        
        if category_filter:
            filter_conditions.append("(l.score_category = %s OR (l.score_category IS NULL AND %s = 'Cold'))")
            query_params.extend([category_filter, category_filter])
        
        if filter_conditions:
            base_query += " AND " + " AND ".join(filter_conditions)
        
        query = base_query + " ORDER BY l.created_at DESC LIMIT %s OFFSET %s"
        query_params.extend([per_page, offset])
        
        cursor.execute(query, query_params)

    leads = cursor.fetchall()
    
    # Get total count for pagination with filters
    if session['role'] == 'super_admin':
        # Build count query with same filters as main query
        base_count_query = """
            SELECT COUNT(*) as total 
            FROM leads l
            WHERE l.company_id = %s
        """
        count_params = [session['company_id']]
        count_conditions = []
        
        if search_query:
            count_conditions.append("(l.name LIKE %s OR l.email LIKE %s OR l.phone LIKE %s OR l.country_preference LIKE %s OR l.course_type LIKE %s OR l.course_level LIKE %s OR l.location LIKE %s)")
            search_param = f'%{search_query}%'
            count_params.extend([search_param, search_param, search_param, search_param, search_param, search_param, search_param])
        
        if status_filter:
            count_conditions.append("l.lead_status = %s")
            count_params.append(status_filter)
        
        if category_filter:
            count_conditions.append("(l.score_category = %s OR (l.score_category IS NULL AND %s = 'Cold'))")
            count_params.extend([category_filter, category_filter])
        
        if count_conditions:
            base_count_query += " AND " + " AND ".join(count_conditions)
        
        cursor.execute(base_count_query, count_params)
    else:
        # Build count query with same filters as main query for regular users
        base_count_query = """
            SELECT COUNT(*) as total 
            FROM leads l
            WHERE l.company_id = %s AND l.assigned_user_id = %s
        """
        count_params = [session['company_id'], session['user_id']]
        count_conditions = []
        
        if search_query:
            count_conditions.append("(l.name LIKE %s OR l.email LIKE %s OR l.phone LIKE %s OR l.country_preference LIKE %s OR l.course_type LIKE %s OR l.course_level LIKE %s OR l.location LIKE %s)")
            search_param = f'%{search_query}%'
            count_params.extend([search_param, search_param, search_param, search_param, search_param, search_param, search_param])
        
        if status_filter:
            count_conditions.append("l.lead_status = %s")
            count_params.append(status_filter)
        
        if category_filter:
            count_conditions.append("(l.score_category = %s OR (l.score_category IS NULL AND %s = 'Cold'))")
            count_params.extend([category_filter, category_filter])
        
        if count_conditions:
            base_count_query += " AND " + " AND ".join(count_conditions)
        
        cursor.execute(base_count_query, count_params)
    
    total_leads = cursor.fetchone()['total']
    total_pages = (total_leads + per_page - 1) // per_page

    # Load counsellors list for bulk-reassign (super_admin only)
    counsellors = []
    if session['role'] == 'super_admin':
        cursor.execute(
            "SELECT id, name FROM users WHERE company_id = %s AND role = 'user' ORDER BY name",
            (session['company_id'],)
        )
        counsellors = cursor.fetchall()

    release_db_connection(conn)

    # Apply scores without filtering (already filtered in SQL)
    leads_with_scores = []
    for lead in leads:
        # Use stored score, default to (0, 'Cold') if NULL
        score = lead.get('score') or 0
        category = lead.get('score_category') or 'Cold'

        lead_dict = dict(lead)
        lead_dict['score'] = score
        lead_dict['category'] = category
        leads_with_scores.append(lead_dict)

    return render_template('leads_list.html',
                         leads=leads_with_scores,
                         page=page,
                         per_page=per_page,
                         total_leads=total_leads,
                         total_pages=total_pages,
                         status_filter=status_filter,
                         category_filter=category_filter,
                         search_query=search_query,
                         counsellors=counsellors)

@app.route('/leads/add', methods=['GET', 'POST'])
@login_required
def add_lead():
    """Add new lead"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        whatsapp = request.form.get('whatsapp', '').strip()
        email = request.form.get('email', '').strip().lower()
        highest_qualification = request.form.get('highest_qualification', '').strip()
        location = request.form.get('location', '').strip()
        age = request.form.get('age', '').strip()
        country_preference = request.form.get('country_preference', '')
        course_type = request.form.get('course_type', '')
        course_level = request.form.get('course_level', '')
        lead_value = request.form.get('lead_value', 0)
        course_id = request.form.get('course_id', '')
        lead_source = request.form.get('lead_source', '')
        registration_amount = request.form.get('registration_amount', 0)
        
        if not name or not phone:
            flash('Name and phone are required', 'error')
            return render_template('add_lead.html')
        
        conn = get_company_db(session['company_id'])
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM leads WHERE company_id = %s AND phone = %s", (session['company_id'], phone))
        if cursor.fetchone():
            release_db_connection(conn)
            flash('Lead with this phone number already exists', 'error')
            return render_template('add_lead.html')
        
        if email:
            cursor.execute("SELECT id FROM leads WHERE company_id = %s AND email = %s", (session['company_id'], email))
            if cursor.fetchone():
                release_db_connection(conn)
                flash('Lead with this email already exists', 'error')
                return render_template('add_lead.html')
        
        cursor.execute("SELECT MAX(serial_number) as max_serial FROM leads WHERE company_id = %s", (session['company_id'],))
        result = cursor.fetchone()
        next_serial = (result['max_serial'] or 0) + 1
        
        assigned_user_id = session['user_id']
        
        cursor.execute("""
            INSERT INTO leads (
                company_id, assigned_user_id, serial_number, name, phone, whatsapp, email,
                highest_qualification, location, age, country_preference,
                course_type, course_level, course_id, lead_source, lead_value, registration_amount
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            session['company_id'], assigned_user_id, next_serial, name, phone, whatsapp, email or None,
            highest_qualification, location, age or None, country_preference,
            course_type, course_level, course_id or None, lead_source, lead_value or 0, registration_amount or 0
        ))
        
        lead_id = cursor.fetchone()['id']
        
        # Calculate and store initial score
        score, category = calculate_lead_score(lead_id, session['company_id'])
        cursor.execute("""
            UPDATE leads 
            SET score = %s, score_category = %s, score_updated_at = CURRENT_TIMESTAMP 
            WHERE id = %s AND company_id = %s
        """, (score, category, lead_id, session['company_id']))
        
        cursor.execute(
            "INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
            (session['company_id'], session['user_id'], 'Created lead', lead_id, request.remote_addr)
        )
        
        conn.commit()
        release_db_connection(conn)

        # ── TIER 4: Notify assigned counsellor of new lead ──────────────────
        create_notification(
            session['company_id'], assigned_user_id, 'new_lead',
            f'New lead assigned: {name}',
            f'A new lead ({name}, {phone}) has been assigned to you.' +
            (f' Country: {country_preference}.' if country_preference else ''),
            lead_id=lead_id
        )

        flash('Lead created successfully', 'success')
        return redirect(url_for('leads_list'))
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM courses WHERE company_id = %s ORDER BY course_name", (session['company_id'],))
    all_courses = cursor.fetchall()
    release_db_connection(conn)
    
    return render_template('add_lead.html', all_courses=all_courses)

@app.route('/leads/view/<int:lead_id>')
@login_required
def view_lead(lead_id):
    """View lead details"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT l.*, u.name as assigned_user_name, u.email as assigned_user_email
        FROM leads l
        LEFT JOIN users u ON l.assigned_user_id = u.id
        WHERE l.id = %s AND l.company_id = %s
    """, (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    if not lead:
        release_db_connection(conn)
        flash('Lead not found', 'error')
        return redirect(url_for('leads_list'))
    
    if session['role'] != 'super_admin' and lead['assigned_user_id'] != session['user_id']:
        release_db_connection(conn)
        flash('Access denied', 'error')
        return redirect(url_for('leads_list'))
    
    cursor.execute("""
        SELECT i.*, u.name as user_name
        FROM interactions i
        JOIN users u ON i.user_id = u.id
        WHERE i.lead_id = %s AND i.company_id = %s
        ORDER BY i.contact_date DESC
    """, (lead_id, session['company_id']))
    interactions = cursor.fetchall()
    
    cursor.execute("SELECT * FROM documents WHERE lead_id = %s AND company_id = %s ORDER BY uploaded_at DESC", (lead_id, session['company_id']))
    documents = cursor.fetchall()
    
    cursor.execute("""
        SELECT f.*, u.name as user_name
        FROM followups f
        JOIN users u ON f.user_id = u.id
        WHERE f.lead_id = %s AND f.company_id = %s
        ORDER BY f.followup_date DESC
    """, (lead_id, session['company_id']))
    followups = cursor.fetchall()
    
    cursor.execute("SELECT id, name, email FROM users WHERE company_id = %s AND role = 'user' ORDER BY name", (session['company_id'],))
    all_users = cursor.fetchall()
    
    cursor.execute("SELECT * FROM courses WHERE company_id = %s ORDER BY course_name", (session['company_id'],))
    all_courses = cursor.fetchall()
    
    current_course = None
    if lead['course_id']:
        cursor.execute("SELECT * FROM courses WHERE id = %s AND company_id = %s", (lead['course_id'], session['company_id']))
        current_course = cursor.fetchone()
    
    release_db_connection(conn)
    
    # Get stored score, calculate if not available
    score, category = get_lead_score(lead_id, session['company_id'])

    # Compute response time for display
    hours_to_first_contact = None
    if lead.get('first_contacted_at') and lead.get('lead_received_date'):
        try:
            delta = lead['first_contacted_at'] - lead['lead_received_date']
            hours_to_first_contact = round(delta.total_seconds() / 3600, 1)
        except Exception:
            pass
    
    return render_template('view_lead.html',
                         lead=lead,
                         interactions=interactions,
                         documents=documents,
                         followups=followups,
                         all_users=all_users,
                         all_courses=all_courses,
                         current_course=current_course,
                         score=score,
                         category=category,
                         hours_to_first_contact=hours_to_first_contact)

@app.route('/leads/<int:lead_id>/update-status', methods=['POST'])
@login_required
def update_lead_status(lead_id):
    """Update lead status via HTMX (for pipeline drag-drop)"""
    new_status = request.form.get('status')
    closed_reason = request.form.get('closed_reason', '').strip()
    closed_reason_detail = request.form.get('closed_reason_detail', '').strip()
    
    if not new_status:
        return 'Error: No status provided', 400
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT assigned_user_id, name, lead_status, first_contacted_at FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    if not lead:
        release_db_connection(conn)
        return 'Error: Lead not found', 404
    
    if session['role'] != 'super_admin' and lead['assigned_user_id'] != session['user_id']:
        release_db_connection(conn)
        return 'Error: Access denied', 403
    
    # Build dynamic SET clause
    set_parts = ["lead_status = %s"]
    params = [new_status]

    # Stamp first_contacted_at if this is the first time lead moves away from "Not Yet Contacted"
    if (lead['lead_status'] == 'Not Yet Contacted' and
        new_status != 'Not Yet Contacted' and
        not lead['first_contacted_at']):
        set_parts.append("first_contacted_at = CURRENT_TIMESTAMP")

    # Capture closed reason for loss/disqualification statuses
    CLOSED_STATUSES = ('Closed - Lost', 'Not Interested', 'Disqualified')
    if new_status in CLOSED_STATUSES:
        if closed_reason:
            set_parts.append("closed_reason = %s")
            params.append(closed_reason)
        if closed_reason_detail:
            set_parts.append("closed_reason_detail = %s")
            params.append(closed_reason_detail)

    params.extend([lead_id, session['company_id']])
    cursor.execute(f"UPDATE leads SET {', '.join(set_parts)} WHERE id = %s AND company_id = %s", params)
    
    cursor.execute(
        "INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
        (session['company_id'], session['user_id'], f'Updated status to: {new_status}', lead_id, request.remote_addr)
    )
    
    conn.commit()
    
    # Get updated lead data
    cursor.execute("SELECT * FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    # Recalculate and update score after status change
    score, category = calculate_lead_score(lead_id, session['company_id'])
    cursor.execute("""
        UPDATE leads 
        SET score = %s, score_category = %s, score_updated_at = CURRENT_TIMESTAMP 
        WHERE id = %s AND company_id = %s
    """, (score, category, lead_id, session['company_id']))
    
    # Get course info if available
    current_course = None
    if lead.get('course_id'):
        cursor.execute("SELECT * FROM courses WHERE id = %s AND company_id = %s", (lead['course_id'], session['company_id']))
        current_course = cursor.fetchone()
    
    release_db_connection(conn)
    
    # Return HTML fragment for status buttons
    return render_template('partials/status_buttons.html', 
                         lead=lead, 
                         score=score, 
                         category=category,
                         current_course=current_course) + \
           f'<span id="currentStatus" class="font-bold bg-white px-2 py-0.5 rounded-md border border-blue-100">{lead["lead_status"]}</span>'

@app.route('/leads/update-details/<int:lead_id>', methods=['POST'])
@login_required
def update_lead_details(lead_id):
    """Update lead value, registration amount, and status (users can update their own leads)"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT assigned_user_id FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    if not lead:
        release_db_connection(conn)
        flash('Lead not found', 'error')
        return redirect(url_for('leads_list'))
    
    if session['role'] != 'super_admin' and lead['assigned_user_id'] != session['user_id']:
        release_db_connection(conn)
        flash('Access denied', 'error')
        return redirect(url_for('leads_list'))
    
    lead_value = request.form.get('lead_value', 0)
    registration_amount = request.form.get('registration_amount', 0)
    lead_status = request.form.get('lead_status', '')
    course_id = request.form.get('course_id', '')
    
    cursor.execute("""
        UPDATE leads 
        SET lead_value = %s, registration_amount = %s, lead_status = %s, course_id = %s
        WHERE id = %s AND company_id = %s
    """, (lead_value or 0, registration_amount or 0, lead_status, course_id or None, lead_id, session['company_id']))
    
    # Recalculate and update score after details change
    score, category = calculate_lead_score(lead_id, session['company_id'])
    cursor.execute("""
        UPDATE leads 
        SET score = %s, score_category = %s, score_updated_at = CURRENT_TIMESTAMP 
        WHERE id = %s AND company_id = %s
    """, (score, category, lead_id, session['company_id']))
    
    cursor.execute(
        "INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
        (session['company_id'], session['user_id'], 'Updated lead details (value/amount/status)', lead_id, request.remote_addr)
    )
    
    conn.commit()
    release_db_connection(conn)
    
    flash('Lead details updated successfully', 'success')
    return redirect(url_for('view_lead', lead_id=lead_id))

@app.route('/leads/edit/<int:lead_id>', methods=['GET', 'POST'])
@login_required
def edit_lead(lead_id):
    """Edit lead (users can edit their own leads, super admin can edit all)"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    if not lead:
        release_db_connection(conn)
        flash('Lead not found', 'error')
        return redirect(url_for('leads_list'))
    
    if session['role'] != 'super_admin' and lead['assigned_user_id'] != session['user_id']:
        release_db_connection(conn)
        flash('Access denied', 'error')
        return redirect(url_for('leads_list'))
    
    if request.method == 'POST':
        old_values = dict(lead)
        
        name = request.form.get('name', '').strip()
        whatsapp = request.form.get('whatsapp', '').strip()
        highest_qualification = request.form.get('highest_qualification', '').strip()
        location = request.form.get('location', '').strip()
        age = request.form.get('age', '').strip()
        country_preference = request.form.get('country_preference', '')
        course_type = request.form.get('course_type', '')
        course_level = request.form.get('course_level', '')
        course_id = request.form.get('course_id', '')
        lead_value = request.form.get('lead_value', 0)
        lead_source = request.form.get('lead_source', '')
        registration_amount = request.form.get('registration_amount', 0)
        lead_status = request.form.get('lead_status', '')

        # ── TIER 3-I: Study-abroad specific fields ───────────────────────────
        budget_range = request.form.get('budget_range', '').strip() or None
        visa_history = request.form.get('visa_history', '').strip() or None
        ielts_score_raw = request.form.get('ielts_score', '').strip()
        ielts_score = float(ielts_score_raw) if ielts_score_raw else None
        ielts_planned_date = request.form.get('ielts_planned_date', '').strip() or None
        preferred_intake = request.form.get('preferred_intake', '').strip() or None
        competitor_consulted = request.form.get('competitor_consulted', '').strip() or None
        referral_name = request.form.get('referral_name', '').strip() or None

        cursor.execute("""
            UPDATE leads
            SET name = %s, whatsapp = %s, highest_qualification = %s, location = %s, age = %s,
                country_preference = %s, course_type = %s, course_level = %s, course_id = %s, lead_source = %s,
                lead_value = %s, registration_amount = %s, lead_status = %s,
                budget_range = %s, visa_history = %s, ielts_score = %s, ielts_planned_date = %s,
                preferred_intake = %s, competitor_consulted = %s, referral_name = %s
            WHERE id = %s AND company_id = %s
        """, (name, whatsapp, highest_qualification, location, age or None,
              country_preference, course_type, course_level, course_id or None, lead_source,
              lead_value or 0, registration_amount or 0, lead_status,
              budget_range, visa_history, ielts_score, ielts_planned_date,
              preferred_intake, competitor_consulted, referral_name,
              lead_id, session['company_id']))
        
        changes = []
        if old_values['name'] != name:
            changes.append(f"Name: '{old_values['name']}' → '{name}'")
        if old_values['whatsapp'] != whatsapp:
            changes.append(f"WhatsApp: '{old_values['whatsapp']}' → '{whatsapp}'")
        if old_values['highest_qualification'] != highest_qualification:
            changes.append(f"Qualification: '{old_values['highest_qualification']}' → '{highest_qualification}'")
        if old_values['location'] != location:
            changes.append(f"Location: '{old_values['location']}' → '{location}'")
        if old_values['age'] != (int(age) if age else None):
            changes.append(f"Age: '{old_values['age']}' → '{age}'")
        if old_values['country_preference'] != country_preference:
            changes.append(f"Country: '{old_values['country_preference']}' → '{country_preference}'")
        if old_values['course_type'] != course_type:
            changes.append(f"Course Type: '{old_values['course_type']}' → '{course_type}'")
        if old_values['course_level'] != course_level:
            changes.append(f"Course Level: '{old_values['course_level']}' → '{course_level}'")
        if old_values['lead_source'] != lead_source:
            changes.append(f"Lead Source: '{old_values['lead_source']}' → '{lead_source}'")
        if old_values['lead_value'] != (float(lead_value) if lead_value else 0):
            changes.append(f"Lead Value: '{old_values['lead_value']}' → '{lead_value}'")
        if old_values['registration_amount'] != (float(registration_amount) if registration_amount else 0):
            changes.append(f"Registration Amount: '{old_values['registration_amount']}' → '{registration_amount}'")
        if old_values['lead_status'] != lead_status:
            changes.append(f"Status: '{old_values['lead_status']}' → '{lead_status}'")
        
        if changes:
            change_details = '; '.join(changes)
            cursor.execute(
                "INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
                (session['company_id'], session['user_id'], f'Edited lead - {change_details}', lead_id, request.remote_addr)
            )
        
        conn.commit()
        release_db_connection(conn)
        
        flash('Lead updated successfully', 'success')
        return redirect(url_for('view_lead', lead_id=lead_id))
    
    cursor.execute("SELECT * FROM courses WHERE company_id = %s ORDER BY course_name", (session['company_id'],))
    all_courses = cursor.fetchall()
    
    release_db_connection(conn)
    
    return render_template('edit_lead.html', lead=lead, all_courses=all_courses)

@app.route('/leads/<int:lead_id>/delete', methods=['GET'])
@login_required
@super_admin_required
def get_delete_modal(lead_id):
    """Get delete modal content via HTMX"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, name FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    release_db_connection(conn)
    
    if not lead:
        return 'Error: Lead not found', 404
    
    return render_template('partials/delete_modal.html', lead=lead)

@app.route('/leads/delete/<int:lead_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_lead(lead_id):
    """Delete lead (super admin only, requires password)"""
    password = request.form.get('password', '')
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT password_hash FROM users WHERE id = %s AND company_id = %s", (session['user_id'], session['company_id']))
    admin = cursor.fetchone()
    
    if not admin or not check_password_hash(admin['password_hash'], password):
        release_db_connection(conn)
        flash('Incorrect password. Please try again.', 'error')
        return redirect(url_for('view_lead', lead_id=lead_id))
    
    cursor.execute("DELETE FROM interactions WHERE lead_id = %s AND company_id = %s", (lead_id, session['company_id']))
    cursor.execute("DELETE FROM documents WHERE lead_id = %s AND company_id = %s", (lead_id, session['company_id']))
    cursor.execute("DELETE FROM followups WHERE lead_id = %s AND company_id = %s", (lead_id, session['company_id']))
    cursor.execute("DELETE FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    
    cursor.execute(
        "INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
        (session['company_id'], session['user_id'], f'Deleted lead ID {lead_id}', None, request.remote_addr)
    )
    
    conn.commit()
    release_db_connection(conn)
    
    flash('Lead deleted successfully', 'success')
    return redirect(url_for('leads_list'))

@app.route('/leads/<int:lead_id>/reassign', methods=['GET'])
@login_required
@super_admin_required
def get_reassign_modal(lead_id):
    """Get reassign modal content via HTMX"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, name, email FROM users WHERE company_id = %s AND role = 'user' ORDER BY name", (session['company_id'],))
    users = cursor.fetchall()
    
    cursor.execute("SELECT id, name FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    release_db_connection(conn)
    
    if not lead:
        return 'Error: Lead not found', 404
    
    return render_template('partials/reassign_modal.html', lead=lead, users=users)

@app.route('/leads/<int:lead_id>/modal-close')
@login_required
def close_modal(lead_id):
    """Return empty string so HTMX clears the modal container (Cancel button)"""
    return ''

@app.route("/modal/custom-date")
@login_required
def custom_date_modal():
    """Serve the custom date range modal partial for HTMX. Accepts optional ?dimension= param."""
    dimension = request.args.get("dimension", "")
    return render_template("partials/custom_date_modal.html", dimension=dimension)

@app.route('/modal/custom-date-export')
@login_required
@super_admin_required
def custom_date_export_modal():
    """Serve the custom date range modal for the leads export (targets /leads/export)."""
    return render_template('partials/custom_date_export_modal.html')

@app.route('/modal/close')
@login_required
def close_modal_generic():
    """Return empty string so HTMX clears any modal container (Cancel button)"""
    return ''

@app.route('/leads/reassign/<int:lead_id>', methods=['POST'])
@login_required
@super_admin_required
def reassign_lead(lead_id):
    """Reassign lead to another user"""
    new_user_id = request.form.get('new_user_id')
    
    if not new_user_id:
        flash('Please select a user', 'error')
        return redirect(url_for('view_lead', lead_id=lead_id))
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Verify the target user belongs to this company — prevents cross-company reassignment
    cursor.execute("SELECT id FROM users WHERE id = %s AND company_id = %s", (new_user_id, session['company_id']))
    if not cursor.fetchone():
        release_db_connection(conn)
        flash('Invalid user selected.', 'error')
        return redirect(url_for('view_lead', lead_id=lead_id))
    
    cursor.execute("UPDATE leads SET assigned_user_id = %s WHERE id = %s AND company_id = %s", (new_user_id, lead_id, session['company_id']))

    # Fetch lead name for the notification
    cursor.execute("SELECT name FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead_row = cursor.fetchone()
    lead_name = lead_row['name'] if lead_row else 'a lead'

    cursor.execute(
        "INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
        (session['company_id'], session['user_id'], f'Reassigned lead to user ID {new_user_id}', lead_id, request.remote_addr)
    )

    conn.commit()
    release_db_connection(conn)

    # ── TIER 4: Notify new counsellor of reassignment ─────────────────────
    create_notification(
        session['company_id'], int(new_user_id), 'lead_assigned',
        f'Lead assigned to you: {lead_name}',
        f'{lead_name} has been reassigned to you by {session["user_name"]}.',
        lead_id=lead_id
    )

    flash('Lead reassigned successfully', 'success')
    return redirect(url_for('view_lead', lead_id=lead_id))

# ============================================================================
# INTERACTION MANAGEMENT
# ============================================================================

@app.route('/leads/<int:lead_id>/add-interaction', methods=['POST'])
@login_required
def add_interaction(lead_id):
    """Add interaction note to lead"""
    note = request.form.get('note', '').strip()
    interaction_type = request.form.get('interaction_type', 'Call').strip()
    interaction_outcome = request.form.get('interaction_outcome', 'Needs Follow-up').strip()

    if not note:
        flash('Interaction note is required', 'error')
        return redirect(url_for('view_lead', lead_id=lead_id))
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Verify lead access
    cursor.execute("SELECT assigned_user_id, lead_status, first_contacted_at FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    if not lead:
        release_db_connection(conn)
        flash('Lead not found', 'error')
        return redirect(url_for('leads_list'))
    
    if session['role'] != 'super_admin' and lead['assigned_user_id'] != session['user_id']:
        release_db_connection(conn)
        flash('Access denied', 'error')
        return redirect(url_for('leads_list'))
    
    # Add interaction with type and outcome
    cursor.execute(
        "INSERT INTO interactions (company_id, lead_id, user_id, interaction_type, interaction_outcome, interaction_note) VALUES (%s, %s, %s, %s, %s, %s)",
        (session['company_id'], lead_id, session['user_id'], interaction_type, interaction_outcome, note)
    )

    # Stamp first_contacted_at if this is the first interaction and lead was never contacted
    if not lead['first_contacted_at']:
        cursor.execute(
            "UPDATE leads SET first_contacted_at = CURRENT_TIMESTAMP WHERE id = %s AND company_id = %s",
            (lead_id, session['company_id'])
        )
    
    # Recalculate score after interaction
    score, category = calculate_lead_score(lead_id, session['company_id'])
    cursor.execute("""
        UPDATE leads 
        SET score = %s, score_category = %s, score_updated_at = CURRENT_TIMESTAMP 
        WHERE id = %s AND company_id = %s
    """, (score, category, lead_id, session['company_id']))
    
    conn.commit()
    release_db_connection(conn)
    
    flash('Interaction added successfully', 'success')
    return redirect(url_for('view_lead', lead_id=lead_id))

# ============================================================================
# DOCUMENT MANAGEMENT
# ============================================================================

@app.route('/leads/<int:lead_id>/add-document', methods=['POST'])
@login_required
def add_document(lead_id):
    """Add document link to lead"""
    document_name = request.form.get('document_name', '').strip()
    document_link = request.form.get('document_link', '').strip()
    
    if not document_name or not document_link:
        flash('Document name and link are required', 'error')
        return redirect(url_for('view_lead', lead_id=lead_id))
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Verify lead access
    cursor.execute("SELECT assigned_user_id FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    if not lead:
        release_db_connection(conn)
        flash('Lead not found', 'error')
        return redirect(url_for('leads_list'))
    
    if session['role'] != 'super_admin' and lead['assigned_user_id'] != session['user_id']:
        release_db_connection(conn)
        flash('Access denied', 'error')
        return redirect(url_for('leads_list'))
    
    # Add document
    cursor.execute(
        "INSERT INTO documents (company_id, lead_id, document_name, document_link) VALUES (%s, %s, %s, %s)",
        (session['company_id'], lead_id, document_name, document_link)
    )
    
    # Recalculate score after document addition
    score, category = calculate_lead_score(lead_id, session['company_id'])
    cursor.execute("""
        UPDATE leads 
        SET score = %s, score_category = %s, score_updated_at = CURRENT_TIMESTAMP 
        WHERE id = %s AND company_id = %s
    """, (score, category, lead_id, session['company_id']))
    
    conn.commit()
    release_db_connection(conn)
    
    flash('Document added successfully', 'success')
    return redirect(url_for('view_lead', lead_id=lead_id))

# ============================================================================
# FOLLOW-UP MANAGEMENT
# ============================================================================

@app.route('/leads/<int:lead_id>/add-followup', methods=['POST'])
@login_required
def add_followup(lead_id):
    """Schedule a follow-up"""
    followup_date = request.form.get('followup_date', '').strip()
    note = request.form.get('note', '').strip()
    
    if not followup_date:
        flash('Follow-up date is required', 'error')
        return redirect(url_for('view_lead', lead_id=lead_id))
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Verify lead access
    cursor.execute("SELECT assigned_user_id FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead = cursor.fetchone()
    
    if not lead:
        release_db_connection(conn)
        flash('Lead not found', 'error')
        return redirect(url_for('leads_list'))
    
    if session['role'] != 'super_admin' and lead['assigned_user_id'] != session['user_id']:
        release_db_connection(conn)
        flash('Access denied', 'error')
        return redirect(url_for('leads_list'))
    
    # Add follow-up
    cursor.execute(
        "INSERT INTO followups (company_id, lead_id, user_id, followup_date, note) VALUES (%s, %s, %s, %s, %s)",
        (session['company_id'], lead_id, session['user_id'], followup_date, note)
    )

    # Fetch lead name for notification
    cursor.execute("SELECT name FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead_row = cursor.fetchone()
    lead_name = lead_row['name'] if lead_row else 'a lead'

    conn.commit()
    release_db_connection(conn)

    # ── TIER 4: Notify counsellor of their scheduled follow-up ────────────
    create_notification(
        session['company_id'], session['user_id'], 'followup_due',
        f'Follow-up scheduled: {lead_name}',
        f'You have a follow-up with {lead_name} scheduled for {followup_date}.' +
        (f' Note: {note}' if note else ''),
        lead_id=lead_id
    )

    flash('Follow-up scheduled successfully', 'success')
    return redirect(url_for('view_lead', lead_id=lead_id))

@app.route('/followups/complete/<int:followup_id>', methods=['POST'])
@login_required
def complete_followup(followup_id):
    """Mark follow-up as completed"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("UPDATE followups SET completed = TRUE WHERE id = %s AND company_id = %s", (followup_id, session['company_id']))
    conn.commit()
    release_db_connection(conn)
    
    flash('Follow-up marked as completed', 'success')
    return redirect(url_for('dashboard'))

@app.route('/followups/acknowledge-escalation/<int:followup_id>', methods=['POST'])
@login_required
@super_admin_required
def acknowledge_escalation(followup_id):
    """Super admin acknowledges an escalated overdue follow-up"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE followups SET escalation_acknowledged = TRUE WHERE id = %s AND company_id = %s",
        (followup_id, session['company_id'])
    )
    conn.commit()
    release_db_connection(conn)
    return redirect(url_for('dashboard'))

@app.route('/pipeline/update-probabilities', methods=['POST'])
@login_required
@super_admin_required
def update_pipeline_probabilities():
    """Update pipeline stage conversion probabilities"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    stages = [
        'Not Yet Contacted', 'Contacted', 'Interested', 'Follow-up',
        'Follow-up Scheduled', 'On-Hold', 'Registered'
    ]
    for stage in stages:
        field = stage.lower().replace(' ', '_').replace('-', '_')
        val = request.form.get(f'prob_{field}', '')
        try:
            prob = max(0, min(100, int(val)))
        except (ValueError, TypeError):
            continue
        cursor.execute("""
            INSERT INTO pipeline_stage_probabilities (company_id, stage, probability, updated_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (company_id, stage) DO UPDATE
            SET probability = EXCLUDED.probability, updated_at = CURRENT_TIMESTAMP
        """, (session['company_id'], stage, prob))
    conn.commit()
    release_db_connection(conn)
    flash('Pipeline probabilities updated', 'success')
    return redirect(url_for('dashboard'))

# ============================================================================
# CSV IMPORT (ALL USERS)
# ============================================================================

@app.route('/leads/import', methods=['GET', 'POST'])
@login_required
@super_admin_required
def import_leads():
    """Import leads from CSV"""
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('import_leads'))
        
        file = request.files['csv_file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('import_leads'))
        
        if not file.filename.endswith('.csv'):
            flash('Only CSV files are allowed', 'error')
            return redirect(url_for('import_leads'))
        
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.reader(stream)
        
        conn = get_company_db(session['company_id'])
        cursor = conn.cursor()
        
        imported_count = 0
        skipped_count = 0
        error_rows = []
        
        next(csv_reader, None)
        
        cursor.execute("SELECT MAX(serial_number) as max_serial FROM leads WHERE company_id = %s", (session['company_id'],))
        result = cursor.fetchone()
        next_serial = (result['max_serial'] or 0) + 1
        
        for row_num, row in enumerate(csv_reader, start=2):
            if len(row) < 7:
                error_rows.append(f"Row {row_num}: Insufficient columns")
                skipped_count += 1
                continue
            
            name, phone, email, country_pref, course_type, course_level, assigned_email = row[:7]
            
            cursor.execute("SELECT id FROM users WHERE company_id = %s AND email = %s", (session['company_id'], assigned_email.strip().lower()))
            user = cursor.fetchone()
            
            if not user:
                error_rows.append(f"Row {row_num}: User '{assigned_email}' not found")
                skipped_count += 1
                continue
            
            cursor.execute("SELECT id FROM leads WHERE company_id = %s AND (phone = %s OR (email = %s AND email IS NOT NULL AND email != ''))", (session['company_id'], phone, email))
            if cursor.fetchone():
                error_rows.append(f"Row {row_num}: Duplicate phone or email")
                skipped_count += 1
                continue
            
            try:
                cursor.execute("""
                    INSERT INTO leads (
                        company_id, assigned_user_id, serial_number, name, phone, email,
                        country_preference, course_type, course_level
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    session['company_id'], user['id'], next_serial, name, phone, email if email else None,
                    country_pref, course_type, course_level
                ))
                next_serial += 1
                imported_count += 1
            except Exception as e:
                error_rows.append(f"Row {row_num}: {str(e)}")
                skipped_count += 1
        
        cursor.execute(
            "INSERT INTO audit_logs (company_id, user_id, action, ip_address) VALUES (%s, %s, %s, %s)",
            (session['company_id'], session['user_id'], f'Imported {imported_count} leads via CSV', request.remote_addr)
        )
        
        conn.commit()
        release_db_connection(conn)
        
        flash(f'Import complete: {imported_count} leads imported, {skipped_count} skipped', 'success')
        
        if error_rows:
            flash('Errors: ' + '; '.join(error_rows[:5]), 'warning')
        
        return redirect(url_for('leads_list'))
    
    return render_template('import_leads.html')

@app.route('/audit-logs')
@login_required
def audit_logs():
    """View audit logs - users see only their lead logs, super admin sees all"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    if session['role'] == 'super_admin':
        # Get total count first
        cursor.execute("""
            SELECT COUNT(*) as total 
            FROM audit_logs a
            WHERE a.company_id = %s
        """, (session['company_id'],))
        total_logs = cursor.fetchone()['total']
        
        # Get logs with pagination
        cursor.execute("""
            SELECT a.*, u.name as user_name, l.name as lead_name, l.phone as lead_phone
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN leads l ON a.lead_id = l.id
            WHERE a.company_id = %s
            ORDER BY a.timestamp DESC
            LIMIT %s OFFSET %s
        """, (session['company_id'], per_page, offset))
    else:
        # Get total count first
        cursor.execute("""
            SELECT COUNT(*) as total 
            FROM audit_logs a
            LEFT JOIN leads l ON a.lead_id = l.id
            WHERE a.company_id = %s AND (l.assigned_user_id = %s OR a.user_id = %s)
        """, (session['company_id'], session['user_id'], session['user_id']))
        total_logs = cursor.fetchone()['total']
        
        # Get logs with pagination
        cursor.execute("""
            SELECT a.*, u.name as user_name, l.name as lead_name, l.phone as lead_phone
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN leads l ON a.lead_id = l.id
            WHERE a.company_id = %s AND (l.assigned_user_id = %s OR a.user_id = %s)
            ORDER BY a.timestamp DESC
            LIMIT %s OFFSET %s
        """, (session['company_id'], session['user_id'], session['user_id'], per_page, offset))
    
    logs = cursor.fetchall()
    total_pages = (total_logs + per_page - 1) // per_page
    
    release_db_connection(conn)
    
    return render_template('audit_logs.html', 
                         logs=logs,
                         page=page,
                         per_page=per_page,
                         total_logs=total_logs,
                         total_pages=total_pages)

@app.route('/reports/user/<int:user_id>')
@login_required
@super_admin_required
def user_report(user_id):
    """Individual user performance report"""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Get user details — must belong to this company (prevents URL enumeration)
    cursor.execute("SELECT * FROM users WHERE id = %s AND company_id = %s", (user_id, session['company_id']))
    user = cursor.fetchone()
    
    if not user:
        release_db_connection(conn)
        flash('User not found', 'error')
        return redirect(url_for('reports'))
    
    # Build date filter
    date_filter = ""
    params = [session['company_id'], user_id]
    
    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        params.extend([start_date, end_date + ' 23:59:59'])
    elif period == 'daily':
        # Daily: Show leads created today OR that had interactions today
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE 
            OR l.id IN (
                SELECT lead_id FROM interactions 
                WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        params = params + [session['company_id']]  # extra company_id for subquery
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"
    
    # Single comprehensive query to get all statistics at once
    cursor.execute(f"""
        SELECT 
            COUNT(DISTINCT l.id) as total_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status != 'Not Yet Contacted' THEN l.id END) as contacted_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Closed - Won' THEN l.id END) as won_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Closed - Lost' THEN l.id END) as lost_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Registered' THEN l.id END) as registered_leads,
            COALESCE(SUM(l.lead_value), 0) as total_value,
            COALESCE(SUM(l.registration_amount), 0) as total_registration
        FROM leads l
        WHERE l.company_id = %s AND l.assigned_user_id = %s {date_filter}
    """, params)
    
    stats = cursor.fetchone()
    
    # Get all lead IDs for bulk scoring
    cursor.execute(f"SELECT id FROM leads l WHERE l.company_id = %s AND l.assigned_user_id = %s {date_filter}", params)
    all_leads = cursor.fetchall()
    lead_ids = [lead['id'] for lead in all_leads]    # Bulk calculate scores for all leads at once
    # Pass user_id for proper filtering
    user_id_for_scoring = session['user_id'] if session['role'] != 'super_admin' else None
    bulk_scores = calculate_lead_scores_bulk(lead_ids, session['company_id'], user_id_for_scoring)
    
    # Count hot, warm, cold leads from bulk results
    hot_count = sum(1 for score, category in bulk_scores.values() if category == 'Hot')
    warm_count = sum(1 for score, category in bulk_scores.values() if category == 'Warm')
    cold_count = sum(1 for score, category in bulk_scores.values() if category == 'Cold')
    
    # Get interaction count
    cursor.execute(f"""
        SELECT COUNT(*) as count 
        FROM interactions i
        JOIN leads l ON i.lead_id = l.id
        WHERE i.company_id = %s AND i.user_id = %s {date_filter.replace('l.created_at', 'i.created_at')}
    """, params)
    interaction_count = cursor.fetchone()['count']
    
    release_db_connection(conn)
    
    conversion_rate = (stats['won_leads'] / stats['total_leads'] * 100) if stats['total_leads'] > 0 else 0
    contact_rate = (stats['contacted_leads'] / stats['total_leads'] * 100) if stats['total_leads'] > 0 else 0
    
    # Calculate date range display
    from datetime import datetime, timedelta
    
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        today = date.today()
        date_range_display = today.strftime('%d/%m/%Y')
    elif period == 'weekly':
        end = date.today()
        start = end - timedelta(days=7)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'monthly':
        end = date.today()
        start = end - timedelta(days=30)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'yearly':
        end = date.today()
        start = end - timedelta(days=365)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    else:
        date_range_display = "All Time"
    
    return render_template('user_report.html',
                         user=user,
                         period=period,
                         start_date=start_date,
                         end_date=end_date,
                         date_range_display=date_range_display,
                         total_leads=stats['total_leads'],
                         contacted_leads=stats['contacted_leads'],
                         total_value=stats['total_value'],
                         total_registration=stats['total_registration'],
                         won_leads=stats['won_leads'],
                         lost_leads=stats['lost_leads'],
                         registered_leads=stats['registered_leads'],
                         conversion_rate=conversion_rate,
                         contact_rate=contact_rate,
                         hot_count=hot_count,
                         warm_count=warm_count,
                         cold_count=cold_count,
                         interaction_count=interaction_count)

@app.route('/reports/comparison')
@login_required
@super_admin_required
def comparison_report():
    """User comparison report"""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE company_id = %s AND role = 'user' ORDER BY name", (session['company_id'],))
    users = cursor.fetchall()
    
    # Build date filter — params here are ONLY the extra date placeholders,
    # NOT the company_id/user_id which are always prepended per query.
    date_filter = ""
    date_params = []
    
    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        date_params = [start_date, end_date + ' 23:59:59']
    elif period == 'daily':
        # The subquery needs its own company_id param
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE 
            OR l.id IN (
                SELECT lead_id FROM interactions WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        date_params = [session['company_id']]
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"
    
    user_stats = []
    
    for user in users:
        # company_id and user_id come first, then any date params
        query_params = [session['company_id'], user['id']] + date_params
        
        cursor.execute(f"""
            SELECT 
                COUNT(DISTINCT l.id) as total_leads,
                COUNT(DISTINCT CASE WHEN l.lead_status != 'Not Yet Contacted' THEN l.id END) as contacted_leads,
                COUNT(DISTINCT CASE WHEN l.lead_status = 'Closed - Won' THEN l.id END) as won_leads,
                COUNT(DISTINCT CASE WHEN l.lead_status = 'Registered' THEN l.id END) as registered_leads,
                COALESCE(SUM(l.registration_amount), 0) as total_registration,
                COUNT(DISTINCT i.id) as interaction_count
            FROM leads l
            LEFT JOIN interactions i ON l.id = i.lead_id AND i.company_id = l.company_id
            WHERE l.company_id = %s AND l.assigned_user_id = %s {date_filter}
        """, query_params)
        
        user_stats_data = cursor.fetchone()
        
        # fetchone() returns None if no leads matched — treat as all zeros
        if not user_stats_data or user_stats_data['total_leads'] == 0:
            user_stats.append({
                'user_id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'total_leads': 0,
                'contacted_leads': 0,
                'won_leads': 0,
                'registered_leads': 0,
                'hot_leads': 0,
                'warm_leads': 0,
                'total_registration': 0,
                'interaction_count': 0,
                'conversion_rate': 0,
                'contact_rate': 0,
                'avg_score': 0
            })
            continue
        
        # Get lead IDs for bulk scoring
        cursor.execute(f"SELECT id FROM leads l WHERE l.company_id = %s AND l.assigned_user_id = %s {date_filter}", query_params)
        user_leads = cursor.fetchall()
        lead_ids = [lead['id'] for lead in user_leads]
        
        # Bulk calculate scores
        score_map = calculate_lead_scores_bulk(lead_ids, session['company_id'])
        
        hot_count = sum(1 for _, (_, cat) in score_map.items() if cat == 'Hot')
        warm_count = sum(1 for _, (_, cat) in score_map.items() if cat == 'Warm')
        total_score = sum(s for _, (s, _) in score_map.items())
        
        avg_score = (total_score / len(user_leads)) if user_leads else 0
        conversion_rate = (user_stats_data['won_leads'] / user_stats_data['total_leads'] * 100) if user_stats_data['total_leads'] > 0 else 0
        contact_rate = (user_stats_data['contacted_leads'] / user_stats_data['total_leads'] * 100) if user_stats_data['total_leads'] > 0 else 0
        
        user_stats.append({
            'user_id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'total_leads': user_stats_data['total_leads'],
            'contacted_leads': user_stats_data['contacted_leads'],
            'won_leads': user_stats_data['won_leads'],
            'registered_leads': user_stats_data.get('registered_leads', 0),
            'hot_leads': hot_count,
            'warm_leads': warm_count,
            'total_registration': user_stats_data['total_registration'],
            'interaction_count': user_stats_data['interaction_count'],
            'conversion_rate': conversion_rate,
            'contact_rate': contact_rate,
            'avg_score': avg_score
        })
    
    # Rank by: conversion rate → registered leads → total registration ₹ → contact rate → total leads
    user_stats.sort(key=lambda x: (
        x['conversion_rate'],
        x['registered_leads'],
        float(x['total_registration']),
        x['contact_rate'],
        x['total_leads']
    ), reverse=True)
    
    # Get top high-potential leads
    cursor.execute(f"""
        SELECT l.id, l.name, l.phone, l.country_preference, u.name as assigned_user_name, l.score, l.score_category 
        FROM leads l 
        LEFT JOIN users u ON l.assigned_user_id = u.id 
        WHERE l.company_id = %s {date_filter}
        ORDER BY l.score DESC NULLS LAST
        LIMIT 3
    """, [session['company_id']] + date_params)
    top_lead_rows = cursor.fetchall()
    
    top_leads = [{
        'id': lead['id'],
        'name': lead['name'],
        'phone': lead['phone'],
        'country': lead['country_preference'],
        'assigned_to': lead['assigned_user_name'],
        'score': lead.get('score') or 0,
        'category': lead.get('score_category') or 'Cold'
    } for lead in top_lead_rows]
        
    release_db_connection(conn)
    
    from datetime import datetime, timedelta
    
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        today = date.today()
        date_range_display = today.strftime('%d/%m/%Y')
    elif period == 'weekly':
        end = date.today()
        start = end - timedelta(days=7)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'monthly':
        end = date.today()
        start = end - timedelta(days=30)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'yearly':
        end = date.today()
        start = end - timedelta(days=365)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    else:
        date_range_display = "All Time"
    
    return render_template('comparison_report.html',
                            user_stats=user_stats,
                            top_leads=top_leads,
                            period=period,
                            start_date=start_date,
                            end_date=end_date,
                            date_range_display=date_range_display)


@app.route('/reports/funnel')
@login_required
def funnel_report():
    """Conversion funnel report showing lead journey"""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    date_filter = ""
    params = [session['company_id']]
    
    if period == 'custom' and start_date and end_date:
        date_filter = "AND created_at BETWEEN %s AND %s"
        params.extend([start_date, end_date + ' 23:59:59'])
    elif period == 'daily':
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE 
            OR l.id IN (
                SELECT lead_id FROM interactions WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        params.append(session['company_id'])
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"
    
    if session['role'] != 'super_admin':
        if date_filter:
            date_filter += " AND assigned_user_id = %s"
        else:
            date_filter = "AND assigned_user_id = %s"
        params.append(session['user_id'])
    
    funnel_stages = [
        ('Total Leads', 'all'),
        ('Contacted', ['Contacted', 'Interested', 'Follow-up', 'Follow-up Scheduled', 'On-Hold', 'Registered', 'Disqualified', 'Not Interested', 'Closed - Won', 'Closed - Lost']),
        ('Interested', ['Interested', 'Follow-up', 'Follow-up Scheduled', 'Registered', 'Closed - Won']),
        ('Follow-up', ['Follow-up', 'Follow-up Scheduled', 'Registered', 'Closed - Won']),
        ('Follow-up Scheduled', ['Follow-up Scheduled', 'Registered', 'Closed - Won']),
        ('Registered',['Registered', 'Closed - Won']),
        ('Closed - Won', ['Closed - Won'])
    ]
    
    funnel_data = []
    
    for stage_name, statuses in funnel_stages:
        if statuses == 'all':
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s {date_filter}"
            cursor.execute(query, params)
        else:
            placeholders = ','.join(['%s' for _ in statuses])
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND l.lead_status IN ({placeholders}) {date_filter}"
            cursor.execute(query, [session['company_id']] + statuses + params[1:])
        
        count = cursor.fetchone()['count']
        funnel_data.append({
            'stage': stage_name,
            'count': count
        })
    
    total_leads = funnel_data[0]['count'] if funnel_data[0]['count'] > 0 else 1
    
    for i, stage in enumerate(funnel_data):
        stage['percentage'] = (stage['count'] / total_leads * 100) if total_leads > 0 else 0
        if i > 0:
            prev_count = funnel_data[i-1]['count']
            stage['drop_off'] = prev_count - stage['count']
            stage['drop_off_percentage'] = (stage['drop_off'] / prev_count * 100) if prev_count > 0 else 0
        else:
            stage['drop_off'] = 0
            stage['drop_off_percentage'] = 0
    
    from datetime import datetime, timedelta
    
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        today = date.today()
        date_range_display = today.strftime('%d/%m/%Y')
    elif period == 'weekly':
        end = date.today()
        start = end - timedelta(days=7)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'monthly':
        end = date.today()
        start = end - timedelta(days=30)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'yearly':
        end = date.today()
        start = end - timedelta(days=365)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    else:
        date_range_display = "All Time"
    
    release_db_connection(conn)
    
    return render_template('funnel_report.html',
                         funnel_data=funnel_data,
                         period=period,
                         start_date=start_date,
                         end_date=end_date,
                         date_range_display=date_range_display)


@app.route('/reports/lead-source')
@login_required
def lead_source_report():
    """Lead source performance report"""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Build date filter
    date_filter = ""
    params = []
    
    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        params = [start_date, end_date + ' 23:59:59']
    elif period == 'daily':
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE 
            OR l.id IN (
                SELECT lead_id FROM interactions 
                WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        params = params + [session['company_id']]
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"
    
    # Add user filter for non-admin
    if session['role'] != 'super_admin':
        if date_filter:
            date_filter += " AND l.assigned_user_id = %s"
        else:
            date_filter = "AND l.assigned_user_id = %s"
        params.append(session['user_id'])
    
    # Get all unique lead sources
    query = f"""
        SELECT DISTINCT lead_source 
        FROM leads l 
        WHERE l.company_id = %s AND lead_source IS NOT NULL AND lead_source != '' {date_filter}
    """
    cursor.execute(query, [session['company_id']] + params)
    sources = [row['lead_source'] for row in cursor.fetchall()]
    
    source_stats = []
    
    for source in sources:
        source_params = [source] + params
        
        # Single comprehensive query per source
        query = f"""
            SELECT 
                COUNT(*) as total_leads,
                COUNT(CASE WHEN l.lead_status != 'Not Yet Contacted' THEN 1 END) as contacted_leads,
                COUNT(CASE WHEN l.lead_status = 'Closed - Won' THEN 1 END) as won_leads,
                COUNT(CASE WHEN l.lead_status = 'Interested' THEN 1 END) as interested_leads,
                COALESCE(SUM(l.registration_amount), 0) as total_revenue
            FROM leads l 
            WHERE l.company_id = %s AND l.lead_source = %s {date_filter}
        """
        cursor.execute(query, [session['company_id']] + source_params)
        source_data = cursor.fetchone()
        
        # Get lead IDs for bulk scoring
        query = f"SELECT id FROM leads l WHERE l.company_id = %s AND lead_source = %s {date_filter}"
        cursor.execute(query, [session['company_id']] + source_params)
        source_leads = cursor.fetchall()
        lead_ids = [lead['id'] for lead in source_leads]
        
        # Bulk calculate scores
        score_map = calculate_lead_scores_bulk(lead_ids, session['company_id'])
        
        hot_count = sum(1 for _, (_, cat) in score_map.items() if cat == 'Hot')
        total_score = sum(score for _, (score, _) in score_map.items())
        
        conversion_rate = (source_data['won_leads'] / source_data['total_leads'] * 100) if source_data['total_leads'] > 0 else 0
        contact_rate = (source_data['contacted_leads'] / source_data['total_leads'] * 100) if source_data['total_leads'] > 0 else 0
        avg_score = (total_score / len(source_leads)) if source_leads else 0
        
        source_stats.append({
            'source': source,
            'total_leads': source_data['total_leads'],
            'contacted_leads': source_data['contacted_leads'],
            'interested_leads': source_data['interested_leads'],
            'won_leads': source_data['won_leads'],
            'hot_leads': hot_count,
            'total_revenue': source_data['total_revenue'],
            'conversion_rate': conversion_rate,
            'contact_rate': contact_rate,
            'avg_score': avg_score
        })
    
    # Sort by conversion rate (best sources first)
    source_stats.sort(key=lambda x: x['conversion_rate'], reverse=True)
    
    # Calculate date range display
    from datetime import datetime, timedelta
    
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        today = date.today()
        date_range_display = today.strftime('%d/%m/%Y')
    elif period == 'weekly':
        end = date.today()
        start = end - timedelta(days=7)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'monthly':
        end = date.today()
        start = end - timedelta(days=30)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'yearly':
        end = date.today()
        start = end - timedelta(days=365)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    else:
        date_range_display = "All Time"
    
    release_db_connection(conn)
    
    return render_template('lead_source_report.html',
                         source_stats=source_stats,
                         period=period,
                         start_date=start_date,
                         end_date=end_date,
                         date_range_display=date_range_display)

@app.route('/reports/analytics')
@login_required
def analytics_report():
    """Multi-dimension analytics report"""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    dimension = request.args.get('dimension', 'lead_source')  # Default dimension
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Build date filter
    date_filter = ""
    params = []
    
    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        params = [start_date, end_date + ' 23:59:59']
    elif period == 'daily':
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE 
            OR l.id IN (
                SELECT lead_id FROM interactions 
                WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        params = params + [session['company_id']]
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"

    
    # Add user filter for non-admin
    if session['role'] != 'super_admin':
        if date_filter:
            date_filter += " AND l.assigned_user_id = %s"
        else:
            date_filter = "AND l.assigned_user_id = %s"
        params.append(session['user_id'])
    
# Get dimension label
    dimension_labels = {
        'lead_source': 'Lead Source',
        'country_preference': 'Country',
        'course_type': 'Course Type',
        'course_level': 'Course Level',
        'location': 'Location',
        'age': 'Age Group',
        'course_name': 'Course Name'
    }
    
    # SECURITY: reject any dimension not in the whitelist — prevents SQL injection
    if dimension not in dimension_labels:
        dimension = 'lead_source'
    dimension_label = dimension_labels[dimension]

    # Get all unique values for selected dimension
    if dimension == 'course_name':
        # Get course names from courses table
        query = f"""
            SELECT DISTINCT c.course_name
            FROM courses c
            JOIN leads l ON l.course_id = c.id
            WHERE l.company_id = %s {date_filter}
        """
        cursor.execute(query, [session['company_id']] + params)
        values = [row['course_name'] for row in cursor.fetchall()]
    elif dimension == 'age':
        # Group ages into ranges
        query = f"""
            SELECT DISTINCT 
                CASE 
                    WHEN age < 18 THEN 'Under 18'
                    WHEN age BETWEEN 18 AND 22 THEN '18-22'
                    WHEN age BETWEEN 23 AND 27 THEN '23-27'
                    WHEN age BETWEEN 28 AND 32 THEN '28-32'
                    WHEN age > 32 THEN 'Above 32'
                    ELSE 'Not Specified'
                END as age_group
            FROM leads l 
            WHERE l.company_id = %s {date_filter}
        """
        cursor.execute(query, [session['company_id']] + params)
        values = [row['age_group'] for row in cursor.fetchall() if row['age_group'] != 'Not Specified']
    else:
        query = f"""
            SELECT DISTINCT {dimension} 
            FROM leads l 
            WHERE l.company_id = %s AND {dimension} IS NOT NULL AND {dimension} != '' {date_filter}
        """
        cursor.execute(query, [session['company_id']] + params)
        values = [row[dimension] for row in cursor.fetchall()]
    
    dimension_stats = []
    
    for value in values:
        if dimension == 'course_name':
            # Query by course name
            course_filter = """AND l.course_id IN (
                SELECT id FROM courses WHERE company_id = %s AND course_name = %s
            )"""
            value_params = [session['company_id'], value] + params
            
            # Total leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s {course_filter} {date_filter}"
            cursor.execute(query, [session['company_id']] + value_params)
            total_leads = cursor.fetchone()['count']
            
            # Contacted leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status != 'Not Yet Contacted' {course_filter} {date_filter}"
            cursor.execute(query, [session['company_id']] + value_params)
            contacted_leads = cursor.fetchone()['count']
            
            # Won leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Closed - Won' {course_filter} {date_filter}"
            cursor.execute(query, [session['company_id']] + value_params)
            won_leads = cursor.fetchone()['count']
            
            # Interested leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Interested' {course_filter} {date_filter}"
            cursor.execute(query, [session['company_id']] + value_params)
            interested_leads = cursor.fetchone()['count']
            
            # Revenue
            query = f"SELECT SUM(registration_amount) as total FROM leads l WHERE l.company_id = %s {course_filter} {date_filter}"
            cursor.execute(query, [session['company_id']] + value_params)
            total_revenue = cursor.fetchone()['total'] or 0
            
            # Get IDs for scoring
            query = f"SELECT l.id FROM leads l WHERE l.company_id = %s {course_filter} {date_filter}"
            cursor.execute(query, [session['company_id']] + value_params)
            dimension_leads = cursor.fetchall()
        elif dimension == 'age':
            # Build age range query
            if value == 'Under 18':
                age_condition = "AND l.age < 18"
            elif value == '18-22':
                age_condition = "AND l.age BETWEEN 18 AND 22"
            elif value == '23-27':
                age_condition = "AND l.age BETWEEN 23 AND 27"
            elif value == '28-32':
                age_condition = "AND l.age BETWEEN 28 AND 32"
            elif value == 'Above 32':
                age_condition = "AND l.age > 32"
            else:
                age_condition = ""
            
            value_params = [session['company_id']] + params
            
            # Total leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s {age_condition} {date_filter}"
            cursor.execute(query, value_params)
            total_leads = cursor.fetchone()['count']
            
            # Contacted leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status != 'Not Yet Contacted' {age_condition} {date_filter}"
            cursor.execute(query, value_params)
            contacted_leads = cursor.fetchone()['count']
            
            # Won leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Closed - Won' {age_condition} {date_filter}"
            cursor.execute(query, value_params)
            won_leads = cursor.fetchone()['count']
            
            # Interested leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Interested' {age_condition} {date_filter}"
            cursor.execute(query, value_params)
            interested_leads = cursor.fetchone()['count']
            
            # Revenue
            query = f"SELECT SUM(registration_amount) as total FROM leads l WHERE l.company_id = %s {age_condition} {date_filter}"
            cursor.execute(query, value_params)
            total_revenue = cursor.fetchone()['total'] or 0
            
            # Get IDs for scoring
            query = f"SELECT id FROM leads l WHERE l.company_id = %s {age_condition} {date_filter}"
            cursor.execute(query, value_params)
            dimension_leads = cursor.fetchall()
        else:
            value_params = [value] + [session['company_id']] + params
            
            # Total leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE {dimension} = %s AND l.company_id = %s {date_filter}"
            cursor.execute(query, value_params)
            total_leads = cursor.fetchone()['count']
            
            # Contacted leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE {dimension} = %s AND l.company_id = %s AND lead_status != 'Not Yet Contacted' {date_filter}"
            cursor.execute(query, value_params)
            contacted_leads = cursor.fetchone()['count']
            
            # Won leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE {dimension} = %s AND l.company_id = %s AND lead_status = 'Closed - Won' {date_filter}"
            cursor.execute(query, value_params)
            won_leads = cursor.fetchone()['count']
            
            # Interested leads
            query = f"SELECT COUNT(*) as count FROM leads l WHERE {dimension} = %s AND l.company_id = %s AND lead_status = 'Interested' {date_filter}"
            cursor.execute(query, value_params)
            interested_leads = cursor.fetchone()['count']
            
            # Revenue
            query = f"SELECT SUM(registration_amount) as total FROM leads l WHERE {dimension} = %s AND l.company_id = %s {date_filter}"
            cursor.execute(query, value_params)
            total_revenue = cursor.fetchone()['total'] or 0
            
            # Get IDs for scoring
            query = f"SELECT id, score, score_category FROM leads l WHERE {dimension} = %s AND l.company_id = %s {date_filter}"
            cursor.execute(query, value_params)
            dimension_leads = cursor.fetchall()
        
        # Use stored scores
        hot_count = sum(1 for lead in dimension_leads if lead.get('score_category') == 'Hot')
        total_score = sum(lead.get('score') or 0 for lead in dimension_leads)
        
        conversion_rate = (won_leads / total_leads * 100) if total_leads > 0 else 0
        contact_rate = (contacted_leads / total_leads * 100) if total_leads > 0 else 0
        avg_score = (total_score / len(dimension_leads)) if dimension_leads else 0
        
        dimension_stats.append({
            'value': value,
            'total_leads': total_leads,
            'contacted_leads': contacted_leads,
            'interested_leads': interested_leads,
            'won_leads': won_leads,
            'hot_leads': hot_count,
            'total_revenue': total_revenue,
            'conversion_rate': conversion_rate,
            'contact_rate': contact_rate,
            'avg_score': avg_score
        })
    
    # Sort by conversion rate
    dimension_stats.sort(key=lambda x: x['conversion_rate'], reverse=True)
    
    # Calculate date range display
    from datetime import datetime, timedelta
    
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        today = date.today()
        date_range_display = today.strftime('%d/%m/%Y')
    elif period == 'weekly':
        end = date.today()
        start = end - timedelta(days=7)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'monthly':
        end = date.today()
        start = end - timedelta(days=30)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'yearly':
        end = date.today()
        start = end - timedelta(days=365)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    else:
        date_range_display = "All Time"
    
    release_db_connection(conn)
    
    return render_template('analytics_report.html',
                         dimension_stats=dimension_stats,
                         dimension=dimension,
                         dimension_label=dimension_label,
                         period=period,
                         start_date=start_date,
                         end_date=end_date,
                         date_range_display=date_range_display)


@app.route('/reports/forecast')
@login_required
def forecast_report():
    """Monthly and quarterly conversion forecast based on lead pipeline"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 15
    offset = (page - 1) * per_page
    
    # Get total count for pagination
    if session['role'] == 'super_admin':
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM leads l
            WHERE l.company_id = %s
            AND l.lead_status NOT IN ('Closed - Won', 'Closed - Lost', 'Not Interested', 'Disqualified')
        """, (session['company_id'],))
    else:
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM leads l
            WHERE l.company_id = %s
            AND l.assigned_user_id = %s 
            AND l.lead_status NOT IN ('Closed - Won', 'Closed - Lost', 'Not Interested', 'Disqualified')
        """, (session['company_id'], session['user_id']))
    
    total_result = cursor.fetchone()
    total_leads_count = total_result['total']
    total_pages = (total_leads_count + per_page - 1) // per_page
    
    # Get paginated leads for calculation with scores and interaction counts
    if session['role'] == 'super_admin':
        cursor.execute("""
            SELECT l.*, u.name as assigned_user_name, u.id as user_id,
                   COALESCE(i.interaction_count, 0) as interaction_count
            FROM leads l
            LEFT JOIN users u ON l.assigned_user_id = u.id
            LEFT JOIN (
                SELECT lead_id, COUNT(*) as interaction_count 
                FROM interactions 
                WHERE company_id = %s
                GROUP BY lead_id
            ) i ON l.id = i.lead_id
            WHERE l.company_id = %s
            AND l.lead_status NOT IN ('Closed - Won', 'Closed - Lost', 'Not Interested', 'Disqualified')
            ORDER BY l.created_at DESC
            LIMIT %s OFFSET %s
        """, (session['company_id'], session['company_id'], per_page, offset))
    else:
        cursor.execute("""
            SELECT l.*, u.name as assigned_user_name, u.id as user_id,
                   COALESCE(i.interaction_count, 0) as interaction_count
            FROM leads l
            LEFT JOIN users u ON l.assigned_user_id = u.id
            LEFT JOIN (
                SELECT lead_id, COUNT(*) as interaction_count 
                FROM interactions 
                WHERE company_id = %s
                GROUP BY lead_id
            ) i ON l.id = i.lead_id
            WHERE l.company_id = %s
            AND l.assigned_user_id = %s 
            AND l.lead_status NOT IN ('Closed - Won', 'Closed - Lost', 'Not Interested', 'Disqualified')
            ORDER BY l.created_at DESC
            LIMIT %s OFFSET %s
        """, (session['company_id'], session['company_id'], session['user_id'], per_page, offset))
    
    active_leads = cursor.fetchall()
    
    # Calculate forecasts for each lead
    forecast_data = []
    total_monthly_probability = 0
    total_monthly_revenue = 0
    total_quarterly_probability = 0
    total_quarterly_revenue = 0
    
    # Group by user for super admin
    user_forecasts = {}
    
    for lead in active_leads:
        # Use stored scores, default to (0, 'Cold') if NULL
        score = lead.get('score') or 0
        category = lead.get('score_category') or 'Cold'
        
        # Calculate days in pipeline
        lead_date = lead['lead_received_date']

        if not lead_date:
            days_in_pipeline = 0
        else:
            if isinstance(lead_date, str):
                lead_date = datetime.strptime(lead_date[:19], '%Y-%m-%d %H:%M:%S')

            if isinstance(lead_date, datetime):
                lead_date = lead_date.date()

            days_in_pipeline = (date.today() - lead_date).days

        # Get interaction count from pre-fetched data
        interaction_count = lead.get('interaction_count') or 0
        
        # Calculate conversion probability based on multiple factors
        base_probability = 0
        
        # Status-based probability
        if lead['lead_status'] == 'Registered':
            base_probability = 0.85  # 85% chance
        elif lead['lead_status'] == 'Follow-up Scheduled':
            base_probability = 0.70
        elif lead['lead_status'] == 'Follow-up':
            base_probability = 0.55
        elif lead['lead_status'] == 'Interested':
            base_probability = 0.40
        elif lead['lead_status'] == 'Contacted':
            base_probability = 0.25
        elif lead['lead_status'] == 'On-Hold':
            base_probability = 0.15
        else:  # Not Yet Contacted
            base_probability = 0.10
        
        # Adjust by score category
        if category == 'Hot':
            base_probability *= 1.2
        elif category == 'Cold':
            base_probability *= 0.7
        
        # Adjust by engagement (interactions)
        if interaction_count >= 5:
            base_probability *= 1.15
        elif interaction_count >= 3:
            base_probability *= 1.08
        elif interaction_count == 0:
            base_probability *= 0.6
        
        # Adjust by time in pipeline (urgency)
        if days_in_pipeline > 60:
            base_probability *= 0.7  # Old leads lose heat
        elif days_in_pipeline < 7:
            base_probability *= 1.1  # Fresh leads have momentum
        
        # Registration amount boost
        if lead['registration_amount'] and lead['registration_amount'] > 0:
            base_probability *= 1.3  # Paid leads are serious
        
        # Cap probability at 95%
        monthly_probability = min(base_probability, 0.95)
        
        # Quarterly probability (3 months window = higher chance)
        quarterly_probability = min(monthly_probability * 1.25, 0.98)
        
        # Expected revenue
        expected_value = float(lead['lead_value']) if lead['lead_value'] is not None else (float(lead['registration_amount'] or 0) * 10 if lead['registration_amount'] else 10000.0)
        monthly_expected_revenue = expected_value * monthly_probability
        quarterly_expected_revenue = expected_value * quarterly_probability
        
        forecast_data.append({
            'lead_id': lead['id'],
            'lead_name': lead['name'],
            'lead_phone': lead['phone'],
            'assigned_user': lead['assigned_user_name'],
            'user_id': lead['user_id'],
            'status': lead['lead_status'],
            'score': score,
            'category': category,
            'days_in_pipeline': days_in_pipeline,
            'interactions': interaction_count,
            'registration_amount': lead['registration_amount'] or 0,
            'expected_value': expected_value,
            'monthly_probability': monthly_probability * 100,
            'monthly_revenue': monthly_expected_revenue,
            'quarterly_probability': quarterly_probability * 100,
            'quarterly_revenue': quarterly_expected_revenue
        })
        
        total_monthly_probability += monthly_probability
        total_monthly_revenue += monthly_expected_revenue
        total_quarterly_probability += quarterly_probability
        total_quarterly_revenue += quarterly_expected_revenue
        
        # Group by user for super admin
        if session['role'] == 'super_admin':
            user_id = lead['user_id']
            if user_id not in user_forecasts:
                user_forecasts[user_id] = {
                    'user_name': lead['assigned_user_name'],
                    'lead_count': 0,
                    'monthly_conversions': 0,
                    'monthly_revenue': 0,
                    'quarterly_conversions': 0,
                    'quarterly_revenue': 0
                }
            user_forecasts[user_id]['lead_count'] += 1
            user_forecasts[user_id]['monthly_conversions'] += monthly_probability
            user_forecasts[user_id]['monthly_revenue'] += monthly_expected_revenue
            user_forecasts[user_id]['quarterly_conversions'] += quarterly_probability
            user_forecasts[user_id]['quarterly_revenue'] += quarterly_expected_revenue
    
    # Sort forecasts by probability
    forecast_data.sort(key=lambda x: x['monthly_probability'], reverse=True)
    
    # Convert user forecasts to list
    user_forecast_list = list(user_forecasts.values())
    user_forecast_list.sort(key=lambda x: x['monthly_revenue'], reverse=True)
    
    # Get current month/quarter info
    now = date.today()
    current_month = now.strftime('%B %Y')
    current_quarter = f"Q{(now.month-1)//3 + 1} {now.year}"
    days_left_in_month = (datetime(now.year, now.month % 12 + 1, 1) - timedelta(days=1)).day - now.day
    
    release_db_connection(conn)
    
    return render_template('forecast_report.html',
                         forecast_data=forecast_data,
                         user_forecasts=user_forecast_list,
                         total_leads=total_leads_count,
                         total_monthly_conversions=int(total_monthly_probability),
                         total_monthly_revenue=total_monthly_revenue,
                         total_quarterly_conversions=int(total_quarterly_probability),
                         total_quarterly_revenue=total_quarterly_revenue,
                         current_month=current_month,
                         current_quarter=current_quarter,
                         days_left_in_month=days_left_in_month,
                         page=page,
                         per_page=per_page,
                         total_pages=total_pages)

@app.route('/reports/forecast/export')
@login_required
def export_forecast():
    """Export forecast report as CSV"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Get all leads for calculation (same logic as forecast_report)
    if session['role'] == 'super_admin':
        cursor.execute("""
            SELECT l.*, u.name as assigned_user_name
            FROM leads l
            LEFT JOIN users u ON l.assigned_user_id = u.id
            WHERE l.company_id = %s
            AND l.lead_status NOT IN ('Closed - Won', 'Closed - Lost', 'Not Interested', 'Disqualified')
        """, (session['company_id'],))
    else:
        cursor.execute("""
            SELECT l.*, u.name as assigned_user_name
            FROM leads l
            LEFT JOIN users u ON l.assigned_user_id = u.id
            WHERE l.company_id = %s AND l.assigned_user_id = %s
            AND l.lead_status NOT IN ('Closed - Won', 'Closed - Lost', 'Not Interested', 'Disqualified')
        """, (session['company_id'], session['user_id']))
    
    active_leads = cursor.fetchall()
    
    # Preload interaction counts
    lead_ids = [lead['id'] for lead in active_leads]

    interaction_counts = {}

    if lead_ids:
        cursor.execute("""
            SELECT lead_id, COUNT(*) as count
            FROM interactions
            WHERE company_id = %s AND lead_id = ANY(%s)
            GROUP BY lead_id
        """, (session['company_id'], lead_ids))
        
        interaction_counts = {row['lead_id']: row['count'] for row in cursor.fetchall()}
    
    # Calculate forecasts (same calculation logic)
    forecast_data = []
    total_monthly_prob = 0
    total_monthly_rev = 0
    total_quarterly_prob = 0
    total_quarterly_rev = 0
    
    for lead in active_leads:
        # Use stored score, default to (0, 'Cold') if NULL
        score = lead.get('score') or 0
        category = lead.get('score_category') or 'Cold'
        
        lead_date = lead['lead_received_date']
        if not lead_date:
            days_in_pipeline = 0
        else:
            if isinstance(lead_date, str):
                lead_date = datetime.strptime(lead_date[:19], '%Y-%m-%d %H:%M:%S')
            if isinstance(lead_date, datetime):
                lead_date = lead_date.date()
            days_in_pipeline = (date.today() - lead_date).days

        interaction_count = interaction_counts.get(lead['id'], 0)
        
        # Calculate probability (same logic as forecast_report)
        base_probability = 0
        if lead['lead_status'] == 'Registered':
            base_probability = 0.85
        elif lead['lead_status'] == 'Follow-up Scheduled':
            base_probability = 0.70
        elif lead['lead_status'] == 'Follow-up':
            base_probability = 0.55
        elif lead['lead_status'] == 'Interested':
            base_probability = 0.40
        elif lead['lead_status'] == 'Contacted':
            base_probability = 0.25
        elif lead['lead_status'] == 'On-Hold':
            base_probability = 0.15
        else:
            base_probability = 0.10
        
        if category == 'Hot':
            base_probability *= 1.2
        elif category == 'Cold':
            base_probability *= 0.7
        
        if interaction_count >= 5:
            base_probability *= 1.15
        elif interaction_count >= 3:
            base_probability *= 1.08
        elif interaction_count == 0:
            base_probability *= 0.6
        
        if days_in_pipeline > 60:
            base_probability *= 0.7
        elif days_in_pipeline < 7:
            base_probability *= 1.1
        
        if lead['registration_amount'] and lead['registration_amount'] > 0:
            base_probability *= 1.3
        
        monthly_probability = min(base_probability, 0.95)
        quarterly_probability = min(monthly_probability * 1.25, 0.98)
        
        expected_value = float(lead['lead_value'] or ((lead['registration_amount'] or 0) * 10 if lead['registration_amount'] else 10000))
        monthly_revenue = expected_value * monthly_probability
        quarterly_revenue = expected_value * quarterly_probability
        
        forecast_data.append({
            'name': lead['name'],
            'phone': lead['phone'],
            'assigned_user': lead['assigned_user_name'],
            'status': lead['lead_status'],
            'score': score,
            'category': category,
            'days_in_pipeline': days_in_pipeline,
            'interactions': interaction_count,
            'monthly_probability': monthly_probability * 100,
            'monthly_revenue': monthly_revenue,
            'quarterly_probability': quarterly_probability * 100,
            'quarterly_revenue': quarterly_revenue
        })
        
        total_monthly_prob += monthly_probability
        total_monthly_rev += monthly_revenue
        total_quarterly_prob += quarterly_probability
        total_quarterly_rev += quarterly_revenue
    
    release_db_connection(conn)
    
    # Sort by monthly probability
    forecast_data.sort(key=lambda x: x['monthly_probability'], reverse=True)
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    now = date.today()
    writer.writerow(['CONVERSION FORECAST REPORT'])
    writer.writerow(['Generated On', now.strftime('%d/%m/%Y %H:%M')])
    writer.writerow(['User', session['user_name']])
    writer.writerow(['Current Month', now.strftime('%B %Y')])
    writer.writerow(['Current Quarter', f"Q{(now.month-1)//3 + 1} {now.year}"])
    writer.writerow([])
    
    # Summary
    writer.writerow(['FORECAST SUMMARY'])
    writer.writerow(['Total Active Leads', len(active_leads)])
    writer.writerow(['Expected Monthly Conversions', f"{total_monthly_prob:.1f}"])
    writer.writerow(['Expected Monthly Revenue', f"₹{total_monthly_rev:.2f}"])
    writer.writerow(['Expected Quarterly Conversions', f"{total_quarterly_prob:.1f}"])
    writer.writerow(['Expected Quarterly Revenue', f"₹{total_quarterly_rev:.2f}"])
    writer.writerow([])
    
    # Lead details
    writer.writerow(['LEAD-WISE FORECAST'])
    if session['role'] == 'super_admin':
        writer.writerow(['Lead Name', 'Phone', 'Assigned To', 'Status', 'Score', 'Category', 'Days in Pipeline', 'Interactions', 'Monthly Probability %', 'Monthly Revenue', 'Quarterly Probability %', 'Quarterly Revenue'])
    else:
        writer.writerow(['Lead Name', 'Phone', 'Status', 'Score', 'Category', 'Days in Pipeline', 'Interactions', 'Monthly Probability %', 'Monthly Revenue', 'Quarterly Probability %', 'Quarterly Revenue'])
    
    for lead in forecast_data:
        if session['role'] == 'super_admin':
            writer.writerow([
                lead['name'],
                lead['phone'],
                lead['assigned_user'],
                lead['status'],
                lead['score'],
                lead['category'],
                lead['days_in_pipeline'],
                lead['interactions'],
                f"{lead['monthly_probability']:.1f}%",
                f"₹{lead['monthly_revenue']:.2f}",
                f"{lead['quarterly_probability']:.1f}%",
                f"₹{lead['quarterly_revenue']:.2f}"
            ])
        else:
            writer.writerow([
                lead['name'],
                lead['phone'],
                lead['status'],
                lead['score'],
                lead['category'],
                lead['days_in_pipeline'],
                lead['interactions'],
                f"{lead['monthly_probability']:.1f}%",
                f"₹{lead['monthly_revenue']:.2f}",
                f"{lead['quarterly_probability']:.1f}%",
                f"₹{lead['quarterly_revenue']:.2f}"
            ])
    
    # Create response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'conversion_forecast_{date.today().strftime("%Y%m%d")}.csv'
    )

@app.route('/courses')
@login_required
@super_admin_required
def courses_list():
    """List all courses (super admin only)"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM courses WHERE company_id = %s ORDER BY course_name", (session['company_id'],))
    courses = cursor.fetchall()
    
    release_db_connection(conn)
    
    return render_template('courses_list.html', courses=courses)


@app.route('/courses/add', methods=['GET', 'POST'])
@login_required
@super_admin_required
def add_course():
    """Add new course (super admin only)"""
    if request.method == 'POST':
        course_name = request.form.get('course_name', '').strip()
        course_fee = request.form.get('course_fee', 0)
        course_duration = request.form.get('course_duration', '').strip()
        course_details_1_link = request.form.get('course_details_1_link', '').strip()
        course_details_2_link = request.form.get('course_details_2_link', '').strip()
        
        if not course_name or not course_fee:
            flash('Course name and fee are required', 'error')
            return render_template('add_course.html')
        
        conn = get_company_db(session['company_id'])
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO courses (company_id, course_name, course_fee, course_duration, course_details_1_link, course_details_2_link)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (session['company_id'], course_name, float(course_fee), course_duration, course_details_1_link, course_details_2_link))
            
            conn.commit()
            release_db_connection(conn)
            
            flash('Course added successfully', 'success')
            return redirect(url_for('courses_list'))
        except Exception as e:
            release_db_connection(conn)
            flash(f'Error adding course: {str(e)}', 'error')
            return render_template('add_course.html')
    
    return render_template('add_course.html')


@app.route('/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@login_required
@super_admin_required
def edit_course(course_id):
    """Edit course (super admin only)"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    if request.method == 'POST':
        course_name = request.form.get('course_name', '').strip()
        course_fee = request.form.get('course_fee', 0)
        course_duration = request.form.get('course_duration', '').strip()
        course_details_1_link = request.form.get('course_details_1_link', '').strip()
        course_details_2_link = request.form.get('course_details_2_link', '').strip()
        
        if not course_name or not course_fee:
            flash('Course name and fee are required', 'error')
        else:
            cursor.execute("""
                UPDATE courses 
                SET course_name = %s, course_fee = %s, course_duration = %s, 
                    course_details_1_link = %s, course_details_2_link = %s
                WHERE id = %s AND company_id = %s
            """, (course_name, float(course_fee), course_duration, course_details_1_link, course_details_2_link, course_id, session['company_id']))
            
            conn.commit()
            flash('Course updated successfully', 'success')
            release_db_connection(conn)
            return redirect(url_for('courses_list'))
    
    cursor.execute("SELECT * FROM courses WHERE id = %s AND company_id = %s", (course_id, session['company_id']))
    course = cursor.fetchone()
    
    release_db_connection(conn)
    
    if not course:
        flash('Course not found', 'error')
        return redirect(url_for('courses_list'))
    
    return render_template('edit_course.html', course=course)


@app.route('/courses/delete/<int:course_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_course(course_id):
    """Delete course (super admin only)"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM courses WHERE id = %s AND company_id = %s", (course_id, session['company_id']))
    conn.commit()
    release_db_connection(conn)
    
    flash('Course deleted successfully', 'success')
    return redirect(url_for('courses_list'))


@app.route('/api/course-fee/<int:course_id>')
@login_required
def get_course_fee(course_id):
    """API endpoint to get course fee"""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    cursor.execute("SELECT course_fee FROM courses WHERE id = %s AND company_id = %s", (course_id, session['company_id']))
    course = cursor.fetchone()
    
    release_db_connection(conn)
    
    if course:
        return {'fee': course['course_fee']}
    return {'fee': 0}

@app.route('/leaderboard')
@login_required
def leaderboard():
    """Gamified leaderboard showing top performers"""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Build date filter
    date_filter = ""
    params = []
    
    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        params = [start_date, end_date + ' 23:59:59']
    elif period == 'daily':
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE 
            OR l.id IN (
                SELECT lead_id FROM interactions 
                WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        params = params + [session['company_id']]
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"

    # Single comprehensive query to get all user statistics at once
    cursor.execute(f"""
        SELECT 
            u.id as user_id,
            u.name,
            u.email,
            COUNT(DISTINCT l.id) as total_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status != 'Not Yet Contacted' THEN l.id END) as contacted_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Closed - Won' THEN l.id END) as won_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Registered' THEN l.id END) as registered_leads,
            COALESCE(SUM(l.registration_amount), 0) as total_registration,
            COUNT(DISTINCT i.id) as interaction_count,
            COUNT(DISTINCT CASE WHEN l.score_category = 'Hot' THEN l.id END) as hot_leads,
            COALESCE(SUM(l.score), 0) as total_score,
            AVG(EXTRACT(EPOCH FROM (l.first_contacted_at - l.lead_received_date))/3600)
                FILTER (WHERE l.first_contacted_at IS NOT NULL) as avg_response_hours,
            COUNT(DISTINCT CASE WHEN l.first_contacted_at IS NOT NULL 
                AND EXTRACT(EPOCH FROM (l.first_contacted_at - l.lead_received_date))/3600 <= 2
                THEN l.id END) as fast_contacts
        FROM users u
        LEFT JOIN leads l ON u.id = l.assigned_user_id {date_filter}
        LEFT JOIN interactions i ON l.id = i.lead_id {date_filter.replace('l.created_at', 'i.created_at')}
        WHERE u.company_id = %s AND u.role = 'user'
        GROUP BY u.id, u.name, u.email
        ORDER BY u.name
    """, [session['company_id']] + params * 2)
    
    users_stats = cursor.fetchall()
    
    leaderboard_data = []
    
    for user_stat in users_stats:
        user_id = user_stat['user_id']
        
        # Use stored scores instead of calculating
        hot_count = user_stat['hot_leads'] or 0
        total_score = user_stat['total_score'] or 0
        
        # Calculate performance score (gamification points)
        performance_score = 0
        performance_score += user_stat['won_leads'] * 100  # 100 points per win
        performance_score += user_stat['registered_leads'] * 50  # 50 points per registration
        performance_score += user_stat['contacted_leads'] * 10  # 10 points per contact
        performance_score += hot_count * 25  # 25 points per hot lead
        performance_score += user_stat['interaction_count'] * 5  # 5 points per interaction
        performance_score += int(user_stat['total_registration'] / 1000)  # 1 point per ₹1000
        
        conversion_rate = (user_stat['won_leads'] / user_stat['total_leads'] * 100) if user_stat['total_leads'] > 0 else 0
        contact_rate = (user_stat['contacted_leads'] / user_stat['total_leads'] * 100) if user_stat['total_leads'] > 0 else 0
        avg_score = (total_score / user_stat['total_leads']) if user_stat['total_leads'] > 0 else 0

        # Tier 2-H: new quality metrics
        avg_response_hours = round(float(user_stat['avg_response_hours']), 1) if user_stat['avg_response_hours'] else None
        fast_contacts = user_stat['fast_contacts'] or 0
        # Bonus points for fast response (≤2h)
        performance_score += fast_contacts * 15

        leaderboard_data.append({
            'user_id': user_id,
            'name': user_stat['name'],
            'email': user_stat['email'],
            'total_leads': user_stat['total_leads'],
            'contacted_leads': user_stat['contacted_leads'],
            'won_leads': user_stat['won_leads'],
            'registered_leads': user_stat['registered_leads'],
            'total_registration': user_stat['total_registration'],
            'interaction_count': user_stat['interaction_count'],
            'hot_leads': hot_count,
            'total_score': total_score,
            'avg_score': avg_score,
            'conversion_rate': conversion_rate,
            'contact_rate': contact_rate,
            'performance_score': performance_score,
            'avg_response_hours': avg_response_hours,
            'fast_contacts': fast_contacts,
            'is_current_user': user_id == session['user_id']
        })
    
    # Sort by performance score, then won leads, then total leads
    # This prevents users with 0 activity from ranking high
    leaderboard_data.sort(key=lambda x: (x['performance_score'], x['won_leads'], x['total_leads']), reverse=True)
    
    # Add rank and badges
    for i, user_data in enumerate(leaderboard_data, start=1):
        user_data['rank'] = i
        
        # Assign badges based on achievements
        badges = []
        if user_data['won_leads'] >= 10:
            badges.append('🌟 Top Closer')
        if user_data['conversion_rate'] >= 20:
            badges.append('🎯 Conversion Master')
        if user_data['hot_leads'] >= 15:
            badges.append('🔥 Hot Lead Hunter')
        if user_data['interaction_count'] >= 100:
            badges.append('💬 Communication Pro')
        if user_data['contact_rate'] >= 90:
            badges.append('⚡ Quick Responder')
        if user_data['total_registration'] >= 100000:
            badges.append('💰 Revenue Champion')
        if user_data['avg_response_hours'] is not None and user_data['avg_response_hours'] <= 2:
            badges.append('🚀 Speed Champion')
        
        user_data['badges'] = badges
    
    # Calculate date range display
    from datetime import datetime, timedelta
    
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        today = date.today()
        date_range_display = today.strftime('%d/%m/%Y')
    elif period == 'weekly':
        end = date.today()
        start = end - timedelta(days=7)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'monthly':
        end = date.today()
        start = end - timedelta(days=30)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    elif period == 'yearly':
        end = date.today()
        start = end - timedelta(days=365)
        date_range_display = f"{start.strftime('%d/%m/%Y')} to {end.strftime('%d/%m/%Y')}"
    else:
        date_range_display = "All Time"
    
    release_db_connection(conn)
    
    return render_template('leaderboard.html',
                         leaderboard_data=leaderboard_data,
                         period=period,
                         start_date=start_date,
                         end_date=end_date,
                         date_range_display=date_range_display)
    

# ============================================================================
# REPORTS
# ============================================================================

@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    
    # Build date filter
    date_filter = ""
    params = [session['company_id']]
    
    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        params.extend([start_date, end_date + ' 23:59:59'])
    elif period == 'daily':
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE 
            OR l.id IN (
                SELECT lead_id FROM interactions WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        params.append(session['company_id'])
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"
    
    # Build user filter
    if session['role'] == 'super_admin':
        user_filter = ""
    else:
        user_filter = "AND l.assigned_user_id = %s"
        params.append(session['user_id'])
    
    # Single comprehensive query to get all statistics at once
    cursor.execute(f"""
        SELECT 
            COUNT(DISTINCT l.id) as total_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status != 'Not Yet Contacted' THEN l.id END) as contacted_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Closed - Won' THEN l.id END) as won_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Closed - Lost' THEN l.id END) as lost_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Registered' THEN l.id END) as registered_leads,
            COALESCE(SUM(l.lead_value), 0) as total_value,
            COALESCE(SUM(l.registration_amount), 0) as total_registration,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Interested' THEN l.id END) as interested_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Follow-up' THEN l.id END) as followup_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Follow-up Scheduled' THEN l.id END) as followup_scheduled_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Not Interested' THEN l.id END) as not_interested_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'On-Hold' THEN l.id END) as on_hold_leads,
            COUNT(DISTINCT CASE WHEN l.lead_status = 'Disqualified' THEN l.id END) as disqualified_leads
        FROM leads l
        WHERE l.company_id = %s {date_filter} {user_filter}
    """, params)
    
    stats = cursor.fetchone()
    
    # Get interaction count - use separate params to avoid corruption
    interaction_params = [session['company_id']]
    
    # Add date parameters if they exist
    if period == 'custom' and start_date and end_date:
        interaction_params.extend([start_date, end_date + ' 23:59:59'])
    elif period == 'daily':
        interaction_params.append(session['company_id'])
    
    # Add user parameter if not super_admin
    if session['role'] != 'super_admin':
        interaction_params.append(session['user_id'])
    
    cursor.execute(f"""
        SELECT COUNT(*) as count 
        FROM interactions i
        JOIN leads l ON i.lead_id = l.id
        WHERE i.company_id = %s {date_filter.replace('l.created_at', 'i.created_at')} {user_filter.replace('l.assigned_user_id', 'i.user_id')}
    """, interaction_params)
    interaction_count = cursor.fetchone()['count']
    
    # Get lead scores from stored DB values (consistent with leads list and drilldown)
    cursor.execute(f"SELECT score_category FROM leads l WHERE l.company_id = %s {date_filter} {user_filter}", params)
    all_scores = cursor.fetchall()
    
    hot_count  = sum(1 for s in all_scores if s.get('score_category') == 'Hot')
    warm_count = sum(1 for s in all_scores if s.get('score_category') == 'Warm')
    cold_count = sum(1 for s in all_scores if s.get('score_category') == 'Cold')
    
    # Calculate rates
    response_rate = (stats['contacted_leads'] / stats['total_leads'] * 100) if stats['total_leads'] > 0 else 0
    conversion_rate = (stats['won_leads'] / stats['total_leads'] * 100) if stats['total_leads'] > 0 else 0
    interest_rate = (stats['interested_leads'] / stats['contacted_leads'] * 100) if stats['contacted_leads'] > 0 else 0
    registration_rate = (stats['registered_leads'] / stats['total_leads'] * 100) if stats['total_leads'] > 0 else 0
    contact_rate = response_rate  # Same as response_rate
    
    # Calculate follow-up leads separately
    followup_leads = stats.get('followup_leads', 0)
    followup_scheduled_leads = stats.get('followup_scheduled_leads', 0)
    not_interested_leads = stats.get('not_interested_leads', 0)
    on_hold_leads = stats.get('on_hold_leads', 0)
    disqualified_leads = stats.get('disqualified_leads', 0)
    
    # Calculate revenue from won and registered leads
    won_revenue = 0  # Could be calculated if needed
    registered_revenue = stats.get('total_registration', 0)  # Same as total_registration
    
    # Calculate date range display
    from datetime import datetime, timedelta
    
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        date_range_display = f"Today ({datetime.now().strftime('%d/%m/%Y')})"
    elif period == 'weekly':
        date_range_display = f"Last 7 days ({(datetime.now() - timedelta(days=7)).strftime('%d/%m/%Y')} - {datetime.now().strftime('%d/%m/%Y')})"
    elif period == 'monthly':
        date_range_display = f"Last 30 days ({(datetime.now() - timedelta(days=30)).strftime('%d/%m/%Y')} - {datetime.now().strftime('%d/%m/%Y')})"
    elif period == 'yearly':
        date_range_display = f"Last 365 days ({(datetime.now() - timedelta(days=365)).strftime('%d/%m/%Y')} - {datetime.now().strftime('%d/%m/%Y')})"
    
    release_db_connection(conn)
    
    return render_template('reports.html',
                         total_leads=stats['total_leads'],
                         contacted_leads=stats['contacted_leads'],
                         won_leads=stats['won_leads'],
                         lost_leads=stats['lost_leads'],
                         registered_leads=stats['registered_leads'],
                         total_value=stats['total_value'],
                         total_registration=stats['total_registration'],
                         hot_count=hot_count,
                         warm_count=warm_count,
                         cold_count=cold_count,
                         response_rate=response_rate,
                         conversion_rate=conversion_rate,
                         interest_rate=interest_rate,
                         registration_rate=registration_rate,
                         contact_rate=contact_rate,
                         followup_leads=followup_leads,
                         followup_scheduled_leads=followup_scheduled_leads,
                         not_interested_leads=not_interested_leads,
                         on_hold_leads=on_hold_leads,
                         disqualified_leads=disqualified_leads,
                         won_revenue=won_revenue,
                         registered_revenue=registered_revenue,
                         interaction_count=interaction_count,
                         period=period,
                         start_date=start_date,
                         end_date=end_date,
                         date_range_display=date_range_display)

@app.route('/reports/drilldown')
@login_required
def report_drilldown():
    """
    Drill-down from any number card on the Reports page.
    Accepts: filter=<preset>, period=<period>, start_date, end_date, page
    filter values: total | contacted | won | lost | registered | interested
                   followup | on_hold | disqualified | not_interested
                   hot | warm | cold
    """
    filter_type = request.args.get('filter', 'total')
    period      = request.args.get('period', 'monthly')
    start_date  = request.args.get('start_date', '')
    end_date    = request.args.get('end_date', '')
    page        = request.args.get('page', 1, type=int)
    per_page    = 15
    offset      = (page - 1) * per_page

    # Whitelist of allowed filter types — prevents injection
    VALID_FILTERS = {
        'total':          ('All Leads',            None),
        'contacted':      ('Contacted Leads',       "l.lead_status != 'Not Yet Contacted'"),
        'not_contacted':  ('Not Yet Contacted',     "l.lead_status = 'Not Yet Contacted'"),
        'won':            ('Closed Won',            "l.lead_status = 'Closed - Won'"),
        'lost':           ('Closed Lost',           "l.lead_status = 'Closed - Lost'"),
        'registered':     ('Registered',            "l.lead_status = 'Registered'"),
        'interested':     ('Interested',            "l.lead_status = 'Interested'"),
        'followup':       ('Follow-up',             "l.lead_status IN ('Follow-up', 'Follow-up Scheduled')"),
        'on_hold':        ('On-Hold',               "l.lead_status = 'On-Hold'"),
        'disqualified':   ('Disqualified',          "l.lead_status = 'Disqualified'"),
        'not_interested': ('Not Interested',        "l.lead_status = 'Not Interested'"),
        'hot':            ('Hot Leads (Score 70+)', "l.score_category = 'Hot'"),
        'warm':           ('Warm Leads (Score 40-69)', "l.score_category = 'Warm'"),
        'cold':           ('Cold Leads (Score <40)', "l.score_category = 'Cold' OR l.score_category IS NULL"),
    }

    if filter_type not in VALID_FILTERS:
        filter_type = 'total'

    label, status_condition = VALID_FILTERS[filter_type]

    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    # ── Date filter ──────────────────────────────────────────────────────────
    date_filter = ""
    date_params = []

    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        date_params = [start_date, end_date + ' 23:59:59']
    elif period == 'daily':
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE
            OR l.id IN (
                SELECT lead_id FROM interactions
                WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        date_params = [session['company_id']]
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"

    # ── User scope filter ────────────────────────────────────────────────────
    user_filter = ""
    user_params = []
    if session['role'] != 'super_admin':
        user_filter = "AND l.assigned_user_id = %s"
        user_params = [session['user_id']]

    # ── Status / score filter ────────────────────────────────────────────────
    status_filter_sql = ""
    if status_condition:
        status_filter_sql = f"AND ({status_condition})"

    # ── Base params list ─────────────────────────────────────────────────────
    base_params = [session['company_id']] + date_params + user_params

    # ── Count query ──────────────────────────────────────────────────────────
    cursor.execute(f"""
        SELECT COUNT(*) AS total
        FROM leads l
        WHERE l.company_id = %s
          {date_filter}
          {user_filter}
          {status_filter_sql}
    """, base_params)
    total_count = cursor.fetchone()['total']
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    # ── Leads query with pagination ──────────────────────────────────────────
    cursor.execute(f"""
        SELECT l.*, u.name AS assigned_user_name
        FROM leads l
        LEFT JOIN users u ON l.assigned_user_id = u.id
        WHERE l.company_id = %s
          {date_filter}
          {user_filter}
          {status_filter_sql}
        ORDER BY l.created_at DESC
        LIMIT %s OFFSET %s
    """, base_params + [per_page, offset])
    leads = cursor.fetchall()

    release_db_connection(conn)

    # ── Date range display ───────────────────────────────────────────────────
    from datetime import datetime, timedelta
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        date_range_display = f"Today ({datetime.now().strftime('%d/%m/%Y')})"
    elif period == 'weekly':
        date_range_display = f"Last 7 days"
    elif period == 'monthly':
        date_range_display = f"Last 30 days"
    elif period == 'yearly':
        date_range_display = f"Last 365 days"
    else:
        date_range_display = "All Time"

    return render_template('report_drilldown.html',
                           leads=leads,
                           label=label,
                           filter_type=filter_type,
                           period=period,
                           start_date=start_date,
                           end_date=end_date,
                           date_range_display=date_range_display,
                           page=page,
                           per_page=per_page,
                           total_count=total_count,
                           total_pages=total_pages)


@app.route('/reports/export')
@login_required
def export_report():
    """Export performance report summary as CSV (not lead details)"""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    # Build date filter
    date_filter = ""
    params = []
    
    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        params = [start_date, end_date + ' 23:59:59']
    elif period == 'daily':
        date_filter = """AND (
            l.created_at::DATE = CURRENT_DATE 
            OR l.id IN (
                SELECT lead_id FROM interactions 
                WHERE company_id = %s AND created_at::DATE = CURRENT_DATE
            )
        )"""
        params = params + [session['company_id']]
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"
    
    # Build user filter
    if session['role'] == 'super_admin':
        user_filter = ""
    else:
        user_filter = "AND l.assigned_user_id = %s"
        params.append(session['user_id'])
    
    # Open DB connection (was missing — caused NameError crash on every export)
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    company_params = [session['company_id']] + params

    # Get statistics (same as reports page)
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s {date_filter} {user_filter}", company_params)
    total_leads = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status != 'Not Yet Contacted' {date_filter} {user_filter}", company_params)
    contacted_leads = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Interested' {date_filter} {user_filter}", company_params)
    interested_leads = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status IN ('Follow-up', 'Follow-up Scheduled') {date_filter} {user_filter}", company_params)
    followup_leads = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Registered' {date_filter} {user_filter}", company_params)
    registered_leads = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Closed - Won' {date_filter} {user_filter}", company_params)
    won_leads = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Closed - Lost' {date_filter} {user_filter}", company_params)
    lost_leads = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Not Interested' {date_filter} {user_filter}", company_params)
    not_interested = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'On-Hold' {date_filter} {user_filter}", company_params)
    on_hold = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT COUNT(*) as count FROM leads l WHERE l.company_id = %s AND lead_status = 'Disqualified' {date_filter} {user_filter}", company_params)
    disqualified = cursor.fetchone()['count']
    
    cursor.execute(f"SELECT SUM(lead_value) as total FROM leads l WHERE l.company_id = %s {date_filter} {user_filter}", company_params)
    total_value = cursor.fetchone()['total'] or 0
    
    cursor.execute(f"SELECT SUM(registration_amount) as total FROM leads l WHERE l.company_id = %s {date_filter} {user_filter}", company_params)
    total_registration = cursor.fetchone()['total'] or 0
    
    cursor.execute(f"SELECT SUM(registration_amount) as total FROM leads l WHERE l.company_id = %s AND lead_status = 'Closed - Won' {date_filter} {user_filter}", company_params)
    won_revenue = cursor.fetchone()['total'] or 0
    
    cursor.execute(f"SELECT SUM(registration_amount) as total FROM leads l WHERE l.company_id = %s AND lead_status = 'Registered' {date_filter} {user_filter}", company_params)
    registered_revenue = cursor.fetchone()['total'] or 0
    
    # Get lead scores using stored values
    cursor.execute(f"SELECT score, score_category FROM leads l WHERE l.company_id = %s {date_filter} {user_filter}", company_params)
    all_scores = cursor.fetchall()
    
    hot_count = sum(1 for score in all_scores if score.get('score_category') == 'Hot')
    warm_count = sum(1 for score in all_scores if score.get('score_category') == 'Warm')
    cold_count = sum(1 for score in all_scores if score.get('score_category') == 'Cold')
    
    release_db_connection(conn)
    
    # Calculate rates
    conversion_rate = (won_leads / total_leads * 100) if total_leads > 0 else 0
    response_rate = (contacted_leads / total_leads * 100) if total_leads > 0 else 0
    registration_rate = (registered_leads / total_leads * 100) if total_leads > 0 else 0
    
    # Get user name
    user_name = session['user_name'] if session['role'] != 'super_admin' else 'All Users'
    
    # Create CSV with summary data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Report header
    writer.writerow(['PERFORMANCE REPORT SUMMARY'])
    writer.writerow(['Period', period.title()])
    writer.writerow(['Date Range', f"{start_date} to {end_date}" if period == 'custom' else f"Last {period}"])
    writer.writerow(['User', user_name])
    writer.writerow(['Generated On', date.today().strftime('%d/%m/%Y %H:%M')])
    writer.writerow([])  # Empty row
    
    # Pipeline Metrics
    writer.writerow(['PIPELINE METRICS'])
    writer.writerow(['Metric', 'Count', 'Percentage'])
    writer.writerow(['Total Leads', total_leads, '100%'])
    writer.writerow(['Contacted', contacted_leads, f"{response_rate:.1f}%"])
    writer.writerow(['Interested', interested_leads, f"{(interested_leads/total_leads*100) if total_leads > 0 else 0:.1f}%"])
    writer.writerow(['Follow-up', followup_leads, f"{(followup_leads/total_leads*100) if total_leads > 0 else 0:.1f}%"])
    writer.writerow(['Registered', registered_leads, f"{registration_rate:.1f}%"])
    writer.writerow(['Closed Won', won_leads, f"{conversion_rate:.1f}%"])
    writer.writerow([])
    
    # Win/Loss Analysis
    writer.writerow(['WIN/LOSS ANALYSIS'])
    writer.writerow(['Status', 'Count'])
    writer.writerow(['Won', won_leads])
    writer.writerow(['Lost', lost_leads])
    writer.writerow(['Not Interested', not_interested])
    writer.writerow(['On-Hold', on_hold])
    writer.writerow(['Disqualified', disqualified])
    writer.writerow([])
    
    # Lead Quality
    writer.writerow(['LEAD QUALITY DISTRIBUTION'])
    writer.writerow(['Category', 'Count', 'Percentage'])
    writer.writerow(['Hot Leads (70+)', hot_count, f"{(hot_count/total_leads*100) if total_leads > 0 else 0:.1f}%"])
    writer.writerow(['Warm Leads (40-69)', warm_count, f"{(warm_count/total_leads*100) if total_leads > 0 else 0:.1f}%"])
    writer.writerow(['Cold Leads (<40)', cold_count, f"{(cold_count/total_leads*100) if total_leads > 0 else 0:.1f}%"])
    writer.writerow([])
    
    # Financial Summary
    writer.writerow(['FINANCIAL SUMMARY'])
    writer.writerow(['Metric', 'Amount (₹)'])
    writer.writerow(['Total Lead Value', f"{total_value:.2f}"])
    writer.writerow(['Total Registration Amount', f"{total_registration:.2f}"])
    writer.writerow(['Confirmed Revenue (Won)', f"{won_revenue:.2f}"])
    writer.writerow(['Pending Revenue (Registered)', f"{registered_revenue:.2f}"])
    writer.writerow([])
    
    # Key Performance Indicators
    writer.writerow(['KEY PERFORMANCE INDICATORS'])
    writer.writerow(['KPI', 'Value'])
    writer.writerow(['Response Rate', f"{response_rate:.1f}%"])
    writer.writerow(['Conversion Rate', f"{conversion_rate:.1f}%"])
    writer.writerow(['Registration Rate', f"{registration_rate:.1f}%"])
    writer.writerow(['Win Rate', f"{(won_leads/(won_leads+lost_leads+not_interested)*100) if (won_leads+lost_leads+not_interested) > 0 else 0:.1f}%"])
    
    # Create response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'performance_report_{period}_{date.today().strftime("%Y%m%d")}.csv'
    )

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================



# ============================================================================
# LEADS EXPORT (SUPER ADMIN ONLY)
# ============================================================================

@app.route('/leads/export')
@login_required
@super_admin_required
def export_leads():
    """Export all leads as CSV in the same format as import, plus Lead Score column."""
    period     = request.args.get('period', 'all')
    start_date = request.args.get('start_date', '')
    end_date   = request.args.get('end_date', '')

    conn   = get_company_db(session['company_id'])
    cursor = conn.cursor()

    # Build date filter on lead creation date
    date_filter = ''
    params = [session['company_id']]

    if period == 'custom' and start_date and end_date:
        date_filter = 'AND l.created_at BETWEEN %s AND %s'
        params.extend([start_date, end_date + ' 23:59:59'])
    elif period == 'daily':
        date_filter = 'AND l.created_at::DATE = CURRENT_DATE'
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"
    # 'all' -> no date filter

    cursor.execute(f"""
        SELECT
            l.name,
            l.phone,
            l.email,
            l.country_preference,
            l.course_type,
            l.course_level,
            u.email   AS assigned_user_email,
            COALESCE(l.score, 0) AS lead_score
        FROM leads l
        LEFT JOIN users u ON l.assigned_user_id = u.id
        WHERE l.company_id = %s {date_filter}
        ORDER BY l.created_at DESC
    """, params)

    leads = cursor.fetchall()

    cursor.execute(
        "INSERT INTO audit_logs (company_id, user_id, action, ip_address) VALUES (%s, %s, %s, %s)",
        (session['company_id'], session['user_id'],
         f'Exported {len(leads)} leads as CSV (period: {period})', request.remote_addr)
    )
    conn.commit()
    release_db_connection(conn)

    # Build CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Phone', 'Email', 'Country Preference',
                     'Course Type', 'Course Level', 'Assigned User Email', 'Lead Score'])
    for lead in leads:
        writer.writerow([
            lead['name'],
            lead['phone'],
            lead['email'] or '',
            lead['country_preference'] or '',
            lead['course_type'] or '',
            lead['course_level'] or '',
            lead['assigned_user_email'] or '',
            lead['lead_score'],
        ])

    output.seek(0)
    filename = f"leads_export_{period}_{date.today().strftime('%Y%m%d')}.csv"
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

# ============================================================================
# STALE LEADS
# ============================================================================

@app.route('/leads/stale')
@login_required
def stale_leads():
    """Show leads with no interaction in 7 / 14 / 30 days."""
    days = request.args.get('days', 14, type=int)
    if days not in (3, 7, 14, 30):
        days = 14

    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    # Leads whose most recent interaction (or creation date if none) is older
    # than `days` days AND are still active (not closed/lost/won/disqualified).
    active_statuses = (
        'Not Yet Contacted', 'Contacted', 'Interested',
        'Follow-up', 'Follow-up Scheduled', 'On-Hold', 'Registered'
    )

    if session['role'] == 'super_admin':
        cursor.execute("""
            SELECT
                l.id, l.name, l.phone, l.whatsapp, l.country_preference,
                l.lead_status, l.score, l.score_category,
                u.name  AS assigned_user_name,
                u.email AS assigned_user_email,
                COALESCE(MAX(i.created_at), l.created_at) AS last_activity,
                (CURRENT_DATE - COALESCE(MAX(i.created_at)::DATE, l.created_at::DATE)) AS days_silent
            FROM leads l
            LEFT JOIN users       u ON l.assigned_user_id = u.id
            LEFT JOIN interactions i ON i.lead_id = l.id AND i.company_id = l.company_id
            WHERE l.company_id = %s
              AND l.lead_status = ANY(%s)
            GROUP BY l.id, l.name, l.phone, l.whatsapp, l.country_preference,
                     l.lead_status, l.score, l.score_category,
                     u.name, u.email, l.created_at
            HAVING (CURRENT_DATE - COALESCE(MAX(i.created_at)::DATE, l.created_at::DATE)) >= %s
            ORDER BY days_silent DESC
        """, (session['company_id'], list(active_statuses), days))
    else:
        cursor.execute("""
            SELECT
                l.id, l.name, l.phone, l.whatsapp, l.country_preference,
                l.lead_status, l.score, l.score_category,
                u.name  AS assigned_user_name,
                u.email AS assigned_user_email,
                COALESCE(MAX(i.created_at), l.created_at) AS last_activity,
                (CURRENT_DATE - COALESCE(MAX(i.created_at)::DATE, l.created_at::DATE)) AS days_silent
            FROM leads l
            LEFT JOIN users       u ON l.assigned_user_id = u.id
            LEFT JOIN interactions i ON i.lead_id = l.id AND i.company_id = l.company_id
            WHERE l.company_id = %s
              AND l.assigned_user_id = %s
              AND l.lead_status = ANY(%s)
            GROUP BY l.id, l.name, l.phone, l.whatsapp, l.country_preference,
                     l.lead_status, l.score, l.score_category,
                     u.name, u.email, l.created_at
            HAVING (CURRENT_DATE - COALESCE(MAX(i.created_at)::DATE, l.created_at::DATE)) >= %s
            ORDER BY days_silent DESC
        """, (session['company_id'], session['user_id'], list(active_statuses), days))

    stale = cursor.fetchall()

    # Group by counsellor for super_admin view
    by_user = {}
    for lead in stale:
        key = lead['assigned_user_name'] or 'Unassigned'
        by_user.setdefault(key, []).append(lead)

    release_db_connection(conn)

    return render_template('stale_leads.html',
                           stale_leads=stale,
                           stale_by_user=by_user,
                           days=days,
                           total=len(stale))


# ============================================================================
# TIER 3-J: LEAD SOURCE ROI REPORT
# ============================================================================

@app.route('/reports/lead-source-roi')
@login_required
@super_admin_required
def lead_source_roi():
    """Lead Source ROI — conversions + revenue + optional budget per source."""
    period = request.args.get('period', 'monthly')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    from datetime import datetime, timedelta
    # Date filter
    date_filter = ""
    params_base = [session['company_id']]
    if period == 'custom' and start_date and end_date:
        date_filter = "AND l.created_at BETWEEN %s AND %s"
        params_base += [start_date, end_date + ' 23:59:59']
    elif period == 'daily':
        date_filter = "AND l.created_at::DATE = CURRENT_DATE"
    elif period == 'weekly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '7 days'"
    elif period == 'monthly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '30 days'"
    elif period == 'yearly':
        date_filter = "AND l.created_at >= CURRENT_DATE - INTERVAL '365 days'"

    # Aggregate leads by source in one query
    cursor.execute(f"""
        SELECT
            COALESCE(NULLIF(l.lead_source, ''), 'Unknown') AS source,
            COUNT(*)                                                         AS total_leads,
            COUNT(*) FILTER (WHERE l.lead_status != 'Not Yet Contacted')     AS contacted_leads,
            COUNT(*) FILTER (WHERE l.lead_status = 'Interested')             AS interested_leads,
            COUNT(*) FILTER (WHERE l.lead_status = 'Registered')             AS registered_leads,
            COUNT(*) FILTER (WHERE l.lead_status = 'Closed - Won')           AS won_leads,
            COALESCE(SUM(l.registration_amount), 0)                          AS total_revenue,
            COALESCE(SUM(l.lead_value), 0)                                   AS pipeline_value
        FROM leads l
        WHERE l.company_id = %s {date_filter}
        GROUP BY source
        ORDER BY won_leads DESC, total_leads DESC
    """, params_base)
    rows = cursor.fetchall()

    # Pull budget data for the current month (best-effort)
    current_month = datetime.now().replace(day=1).strftime('%Y-%m-%d')
    cursor.execute("""
        SELECT source, budget_spent
        FROM lead_source_budgets
        WHERE company_id = %s AND month = %s
    """, (session['company_id'], current_month))
    budgets = {r['source']: float(r['budget_spent']) for r in cursor.fetchall()}

    # Get all users for budget form
    cursor.execute("SELECT id, name FROM users WHERE company_id = %s AND role = 'user' ORDER BY name", (session['company_id'],))
    users = cursor.fetchall()

    release_db_connection(conn)

    # Enrich rows with derived metrics
    source_data = []
    for row in rows:
        total = row['total_leads'] or 1  # avoid division by zero
        won = row['won_leads'] or 0
        revenue = float(row['total_revenue'])
        budget = budgets.get(row['source'], 0.0)
        conversion_rate = (won / total) * 100
        contact_rate = (row['contacted_leads'] / total) * 100
        cost_per_lead = budget / total if budget > 0 else None
        cost_per_conversion = budget / won if (budget > 0 and won > 0) else None
        roi = ((revenue - budget) / budget * 100) if budget > 0 else None
        source_data.append({
            'source': row['source'],
            'total_leads': row['total_leads'],
            'contacted_leads': row['contacted_leads'],
            'interested_leads': row['interested_leads'],
            'registered_leads': row['registered_leads'],
            'won_leads': won,
            'total_revenue': revenue,
            'pipeline_value': float(row['pipeline_value']),
            'contact_rate': contact_rate,
            'conversion_rate': conversion_rate,
            'budget': budget,
            'cost_per_lead': cost_per_lead,
            'cost_per_conversion': cost_per_conversion,
            'roi': roi,
        })

    # Date range display
    if period == 'custom' and start_date and end_date:
        date_range_display = f"{datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')} to {datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')}"
    elif period == 'daily':
        date_range_display = f"Today ({datetime.now().strftime('%d/%m/%Y')})"
    elif period == 'weekly':
        date_range_display = f"Last 7 days"
    elif period == 'monthly':
        date_range_display = f"Last 30 days"
    elif period == 'yearly':
        date_range_display = f"Last 365 days"
    else:
        date_range_display = "All Time"

    return render_template('lead_source_roi.html',
                           source_data=source_data,
                           period=period,
                           start_date=start_date,
                           end_date=end_date,
                           date_range_display=date_range_display,
                           current_month=current_month)


@app.route('/reports/lead-source-roi/update-budget', methods=['POST'])
@login_required
@super_admin_required
def update_lead_source_budget():
    """Save marketing budget for a source/month."""
    source = request.form.get('source', '').strip()
    month = request.form.get('month', '').strip()
    budget_spent = request.form.get('budget_spent', '0').strip()
    if not source or not month:
        flash('Source and month are required', 'error')
        return redirect(url_for('lead_source_roi'))
    try:
        budget_val = float(budget_spent)
    except ValueError:
        flash('Invalid budget amount', 'error')
        return redirect(url_for('lead_source_roi'))
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO lead_source_budgets (company_id, source, month, budget_spent)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (company_id, source, month) DO UPDATE
        SET budget_spent = EXCLUDED.budget_spent
    """, (session['company_id'], source, month, budget_val))
    conn.commit()
    release_db_connection(conn)
    flash(f'Budget updated for {source}', 'success')
    return redirect(url_for('lead_source_roi'))


# ============================================================================
# TIER 3-K: STALE LEAD REASSIGNMENT RULES
# ============================================================================

@app.route('/settings/stale-rules', methods=['GET', 'POST'])
@login_required
@super_admin_required
def stale_lead_rules_settings():
    """Manage auto-reassignment rules for stale leads."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'save_rule':
            days = request.form.get('days_threshold', 14)
            user_id = request.form.get('auto_reassign_to_user_id', '') or None
            enabled = request.form.get('enabled') == 'on'
            try:
                days = max(1, int(days))
            except (ValueError, TypeError):
                days = 14
            cursor.execute("""
                INSERT INTO stale_lead_rules (company_id, days_threshold, auto_reassign_to_user_id, enabled)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (company_id) DO UPDATE
                SET days_threshold = EXCLUDED.days_threshold,
                    auto_reassign_to_user_id = EXCLUDED.auto_reassign_to_user_id,
                    enabled = EXCLUDED.enabled
            """, (session['company_id'], days, user_id, enabled))
            conn.commit()
            flash('Auto-reassignment rule saved', 'success')
        elif action == 'run_now':
            _apply_stale_lead_rules(session['company_id'])
            flash('Stale lead reassignment rules applied now', 'success')
        release_db_connection(conn)
        return redirect(url_for('stale_lead_rules_settings'))

    cursor.execute("""
        SELECT r.*, u.name as reassign_user_name
        FROM stale_lead_rules r
        LEFT JOIN users u ON r.auto_reassign_to_user_id = u.id
        WHERE r.company_id = %s
    """, (session['company_id'],))
    rule = cursor.fetchone()

    cursor.execute("SELECT id, name FROM users WHERE company_id = %s AND role = 'user' ORDER BY name", (session['company_id'],))
    users = cursor.fetchall()

    release_db_connection(conn)
    return render_template('stale_rules.html', rule=rule, users=users)


def _apply_stale_lead_rules(company_id):
    """
    Apply stale-lead auto-reassignment for a company.
    Called on stale_rules_settings POST and can be called from a scheduler.
    """
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT * FROM stale_lead_rules
            WHERE company_id = %s AND enabled = TRUE
        """, (company_id,))
        rule = cursor.fetchone()
        if not rule or not rule['auto_reassign_to_user_id']:
            return

        days = rule['days_threshold']
        target_user = rule['auto_reassign_to_user_id']
        active_statuses = [
            'Not Yet Contacted', 'Contacted', 'Interested',
            'Follow-up', 'Follow-up Scheduled', 'On-Hold'
        ]

        cursor.execute("""
            SELECT l.id, l.name, l.assigned_user_id,
                   COALESCE(MAX(i.created_at), l.created_at) AS last_activity
            FROM leads l
            LEFT JOIN interactions i ON i.lead_id = l.id AND i.company_id = l.company_id
            WHERE l.company_id = %s
              AND l.lead_status = ANY(%s)
              AND l.assigned_user_id != %s
            GROUP BY l.id, l.name, l.assigned_user_id, l.created_at
            HAVING (CURRENT_DATE - COALESCE(MAX(i.created_at)::DATE, l.created_at::DATE)) >= %s
        """, (company_id, active_statuses, target_user, days))
        stale = cursor.fetchall()

        reassigned = 0
        for lead in stale:
            cursor.execute("""
                UPDATE leads SET assigned_user_id = %s WHERE id = %s AND company_id = %s
            """, (target_user, lead['id'], company_id))
            cursor.execute("""
                INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address)
                VALUES (%s, %s, %s, %s, %s)
            """, (company_id, target_user,
                  f'Auto-reassigned (stale {days}d rule): was user {lead["assigned_user_id"]}',
                  lead['id'], 'system'))
            reassigned += 1

        conn.commit()
        print(f"✅ Stale rule applied: {reassigned} leads reassigned for company {company_id}")
    except Exception as e:
        print(f"❌ Stale rule error: {e}")
    finally:
        release_db_connection(conn)


# ============================================================================
# TIER 3-L: TODAY'S PRIORITY LEADS (dashboard helper endpoint)
# ============================================================================

@app.route('/api/priority-leads')
@login_required
def priority_leads_api():
    """
    Return today's top-priority leads as JSON for the dashboard widget.
    Sorted by: (1) hot score descending, (2) days since last contact descending.
    Capped at 10.
    """
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    base_filter = "l.company_id = %s AND l.lead_status NOT IN ('Closed - Won','Closed - Lost','Not Interested','Disqualified')"
    params = [session['company_id']]
    if session['role'] != 'super_admin':
        base_filter += " AND l.assigned_user_id = %s"
        params.append(session['user_id'])

    cursor.execute(f"""
        SELECT
            l.id, l.name, l.phone, l.whatsapp, l.lead_status,
            l.score, l.score_category, l.country_preference,
            u.name AS assigned_user_name,
            COALESCE(MAX(i.created_at), l.created_at) AS last_activity,
            (CURRENT_DATE - COALESCE(MAX(i.created_at)::DATE, l.created_at::DATE)) AS days_silent
        FROM leads l
        LEFT JOIN users u ON l.assigned_user_id = u.id
        LEFT JOIN interactions i ON i.lead_id = l.id AND i.company_id = l.company_id
        WHERE {base_filter}
        GROUP BY l.id, l.name, l.phone, l.whatsapp, l.lead_status,
                 l.score, l.score_category, l.country_preference,
                 u.name, l.created_at
        ORDER BY
            CASE l.score_category WHEN 'Hot' THEN 0 WHEN 'Warm' THEN 1 ELSE 2 END,
            days_silent DESC,
            l.score DESC
        LIMIT 10
    """, params)
    leads = cursor.fetchall()
    release_db_connection(conn)

    result = []
    for lead in leads:
        result.append({
            'id': lead['id'],
            'name': lead['name'],
            'phone': lead['phone'],
            'whatsapp': lead['whatsapp'],
            'lead_status': lead['lead_status'],
            'score': lead['score'],
            'score_category': lead['score_category'],
            'country_preference': lead['country_preference'],
            'assigned_user_name': lead['assigned_user_name'],
            'days_silent': int(lead['days_silent']) if lead['days_silent'] is not None else 0,
        })
    return jsonify(result)


# ============================================================================
# TIER 3-I: EDIT LEAD — extended fields save/load (handled in existing edit_lead)
# ============================================================================

# ============================================================================
# ACTIVITY HEATMAP
# ============================================================================

@app.route('/reports/activity')
@login_required
def activity_report():
    """Team activity heatmap — interactions per day for the last 12 weeks."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    # 12 weeks of data
    if session['role'] == 'super_admin':
        cursor.execute("""
            SELECT
                i.created_at::DATE          AS activity_date,
                COUNT(*)                    AS interaction_count,
                u.name                      AS counsellor
            FROM interactions i
            LEFT JOIN users u ON i.user_id = u.id
            WHERE i.company_id = %s
              AND i.created_at >= CURRENT_DATE - INTERVAL '84 days'
            GROUP BY activity_date, u.name
            ORDER BY activity_date
        """, (session['company_id'],))
    else:
        cursor.execute("""
            SELECT
                i.created_at::DATE  AS activity_date,
                COUNT(*)            AS interaction_count,
                u.name              AS counsellor
            FROM interactions i
            LEFT JOIN users u ON i.user_id = u.id
            WHERE i.company_id = %s
              AND i.user_id = %s
              AND i.created_at >= CURRENT_DATE - INTERVAL '84 days'
            GROUP BY activity_date, u.name
            ORDER BY activity_date
        """, (session['company_id'], session['user_id']))

    rows = cursor.fetchall()

    # Also get per-counsellor weekly totals for the bar breakdown
    if session['role'] == 'super_admin':
        cursor.execute("""
            SELECT
                u.name                                          AS counsellor,
                DATE_TRUNC('week', i.created_at)::DATE         AS week_start,
                COUNT(*)                                        AS weekly_count
            FROM interactions i
            LEFT JOIN users u ON i.user_id = u.id
            WHERE i.company_id = %s
              AND i.created_at >= CURRENT_DATE - INTERVAL '84 days'
            GROUP BY counsellor, week_start
            ORDER BY week_start, counsellor
        """, (session['company_id'],))
    else:
        cursor.execute("""
            SELECT
                u.name                                          AS counsellor,
                DATE_TRUNC('week', i.created_at)::DATE         AS week_start,
                COUNT(*)                                        AS weekly_count
            FROM interactions i
            LEFT JOIN users u ON i.user_id = u.id
            WHERE i.company_id = %s
              AND i.user_id = %s
              AND i.created_at >= CURRENT_DATE - INTERVAL '84 days'
            GROUP BY counsellor, week_start
            ORDER BY week_start, counsellor
        """, (session['company_id'], session['user_id']))

    weekly_rows = cursor.fetchall()
    release_db_connection(conn)

    # Build a date→count map for the heatmap grid
    from datetime import timedelta
    today = date.today()
    start_date = today - timedelta(days=83)

    # date_map: {date_str: total_count}
    date_map = {}
    for row in rows:
        d = str(row['activity_date'])
        date_map[d] = date_map.get(d, 0) + row['interaction_count']

    # Build ordered list of all 84 days with counts
    calendar_days = []
    d = start_date
    while d <= today:
        ds = str(d)
        calendar_days.append({
            'date': ds,
            'count': date_map.get(ds, 0),
            'dow': d.strftime('%a'),
            'label': d.strftime('%d %b')
        })
        d += timedelta(days=1)

    max_count = max((day['count'] for day in calendar_days), default=1) or 1

    # Per-counsellor summary
    counsellor_totals = {}
    for row in rows:
        c = row['counsellor'] or 'Unknown'
        counsellor_totals[c] = counsellor_totals.get(c, 0) + row['interaction_count']
    counsellor_summary = sorted(counsellor_totals.items(), key=lambda x: -x[1])

    # Day-of-week totals (Mon-Sun)
    dow_totals = {d: 0 for d in ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']}
    for day in calendar_days:
        dow = day['dow']
        if dow in dow_totals:
            dow_totals[dow] += day['count']

    total_interactions = sum(d['count'] for d in calendar_days)
    active_days = sum(1 for d in calendar_days if d['count'] > 0)

    return render_template('activity_report.html',
                           calendar_days=calendar_days,
                           max_count=max_count,
                           counsellor_summary=counsellor_summary,
                           dow_totals=dow_totals,
                           total_interactions=total_interactions,
                           active_days=active_days,
                           weekly_rows=weekly_rows)


# ============================================================================
# TIER 4: INTERNAL NOTIFICATION ROUTES
# ============================================================================

@app.route('/notifications')
@login_required
def notifications_page():
    """Full notifications page — all notifications for the current user."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM notifications
        WHERE company_id = %s AND user_id = %s
        ORDER BY created_at DESC
        LIMIT 100
    """, (session['company_id'], session['user_id']))
    notifs = cursor.fetchall()

    # Mark all as read when user opens the page
    cursor.execute("""
        UPDATE notifications SET is_read = TRUE
        WHERE company_id = %s AND user_id = %s AND is_read = FALSE
    """, (session['company_id'], session['user_id']))
    conn.commit()
    release_db_connection(conn)

    return render_template('notifications.html', notifications=notifs)


@app.route('/api/notifications')
@login_required
def notifications_api():
    """Return recent unread notifications as JSON for the navbar dropdown."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, type, title, body, lead_id, is_read,
               to_char(created_at, 'DD Mon, HH12:MI AM') as created_fmt
        FROM notifications
        WHERE company_id = %s AND user_id = %s
        ORDER BY created_at DESC
        LIMIT 10
    """, (session['company_id'], session['user_id']))
    notifs = cursor.fetchall()
    release_db_connection(conn)

    return jsonify([dict(n) for n in notifs])


@app.route('/notifications/mark-read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    """Mark a single notification as read."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE notifications SET is_read = TRUE WHERE id = %s AND company_id = %s AND user_id = %s",
        (notif_id, session['company_id'], session['user_id'])
    )
    conn.commit()
    release_db_connection(conn)
    return '', 204


@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read for the current user."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE notifications SET is_read = TRUE WHERE company_id = %s AND user_id = %s AND is_read = FALSE",
        (session['company_id'], session['user_id'])
    )
    conn.commit()
    release_db_connection(conn)
    return jsonify({'ok': True})


@app.route('/notifications/clear-all', methods=['POST'])
@login_required
def clear_all_notifications():
    """Delete all read notifications for the current user."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM notifications WHERE company_id = %s AND user_id = %s AND is_read = TRUE",
        (session['company_id'], session['user_id'])
    )
    conn.commit()
    release_db_connection(conn)
    flash('Cleared all read notifications', 'success')
    return redirect(url_for('notifications_page'))


# ============================================================================
# TIER 4: STUDENT SELF-SERVE PORTAL ROUTES
# ============================================================================

@app.route('/leads/<int:lead_id>/generate-portal', methods=['POST'])
@login_required
def generate_portal_link(lead_id):
    """Generate (or retrieve existing) portal token for a lead."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    # Verify lead access
    cursor.execute(
        "SELECT id, name, assigned_user_id FROM leads WHERE id = %s AND company_id = %s",
        (lead_id, session['company_id'])
    )
    lead = cursor.fetchone()
    if not lead:
        release_db_connection(conn)
        flash('Lead not found', 'error')
        return redirect(url_for('leads_list'))
    if session['role'] != 'super_admin' and lead['assigned_user_id'] != session['user_id']:
        release_db_connection(conn)
        flash('Access denied', 'error')
        return redirect(url_for('leads_list'))

    # Check if portal already exists for this lead
    cursor.execute(
        "SELECT token FROM student_portals WHERE company_id = %s AND lead_id = %s",
        (session['company_id'], lead_id)
    )
    existing = cursor.fetchone()
    if existing:
        token = existing['token']
    else:
        token = secrets.token_urlsafe(24)
        cursor.execute(
            "INSERT INTO student_portals (company_id, lead_id, token) VALUES (%s, %s, %s)",
            (session['company_id'], lead_id, token)
        )
        conn.commit()

    release_db_connection(conn)

    portal_url = request.host_url.rstrip('/') + f'/portal/{token}'
    # Build WhatsApp pre-filled message link
    company_name = session.get('company_name', 'our team')
    wa_num = ''
    # Try to get lead's whatsapp number
    conn2 = get_company_db(session['company_id'])
    c2 = conn2.cursor()
    c2.execute("SELECT whatsapp, phone FROM leads WHERE id = %s AND company_id = %s", (lead_id, session['company_id']))
    lead_contact = c2.fetchone()
    release_db_connection(conn2)

    if lead_contact:
        raw = (lead_contact['whatsapp'] or lead_contact['phone'] or '').replace('+', '').replace(' ', '').replace('-', '')
        if raw:
            wa_num = raw

    wa_message = (
        f"Hi {lead['name']}! 👋 Here's your personal application tracking link from {company_name}. "
        f"You can check your status and upload documents here: {portal_url} — no login needed. "
        f"Feel free to WhatsApp me if you have questions! 😊"
    )
    wa_link = f"https://wa.me/{wa_num}?text={wa_message}" if wa_num else None

    return render_template(
        'partials/portal_link_modal.html',
        lead=lead,
        portal_url=portal_url,
        wa_link=wa_link,
        wa_message=wa_message
    )


@app.route('/portal/<token>')
def student_portal(token):
    """
    Public student self-serve portal page.
    No login required — access controlled by unguessable token.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Resolve token to company_id + lead_id
    cursor.execute(
        "SELECT * FROM student_portals WHERE token = %s",
        (token,)
    )
    portal = cursor.fetchone()
    release_db_connection(conn)

    if not portal:
        return render_template('portal_not_found.html'), 404

    company_id = portal['company_id']
    lead_id = portal['lead_id']

    conn2 = get_company_db(company_id)
    cursor2 = conn2.cursor()

    # Update last_accessed_at
    cursor2.execute(
        "UPDATE student_portals SET last_accessed_at = CURRENT_TIMESTAMP WHERE token = %s",
        (token,)
    )

    # Fetch lead details — users table has no phone column, use whatsapp from leads
    cursor2.execute("""
        SELECT l.*, u.name as counsellor_name,
               c.company_name
        FROM leads l
        LEFT JOIN users u ON l.assigned_user_id = u.id
        LEFT JOIN companies c ON l.company_id = c.id
        WHERE l.id = %s AND l.company_id = %s
    """, (lead_id, company_id))
    lead = cursor2.fetchone()

    # Fetch documents already uploaded
    cursor2.execute("""
        SELECT * FROM documents WHERE lead_id = %s AND company_id = %s
        ORDER BY uploaded_at DESC
    """, (lead_id, company_id))
    documents = cursor2.fetchall()

    conn2.commit()
    release_db_connection(conn2)

    if not lead:
        return render_template('portal_not_found.html'), 404

    # Build application stage timeline based on lead_status
    stages = [
        ('Enquiry Received',    ['Not Yet Contacted', 'Contacted', 'Interested', 'Follow-up', 'Follow-up Scheduled', 'On-Hold', 'Registered', 'Closed - Won']),
        ('Counsellor Assigned', ['Contacted', 'Interested', 'Follow-up', 'Follow-up Scheduled', 'On-Hold', 'Registered', 'Closed - Won']),
        ('Application Review',  ['Interested', 'Follow-up', 'Follow-up Scheduled', 'On-Hold', 'Registered', 'Closed - Won']),
        ('Registration',        ['Registered', 'Closed - Won']),
        ('Visa Application',    ['Closed - Won']),
        ('Visa Approved 🎉',    []),
    ]

    current_status = lead['lead_status'] or 'Not Yet Contacted'
    stage_states = []
    found_current = False
    for stage_name, active_statuses in stages:
        if current_status in active_statuses:
            stage_states.append({'name': stage_name, 'state': 'complete'})
        elif not found_current:
            stage_states.append({'name': stage_name, 'state': 'current'})
            found_current = True
        else:
            stage_states.append({'name': stage_name, 'state': 'upcoming'})

    # Build counsellor WhatsApp link using lead's own whatsapp field on the counsellor's
    # whatsapp isn't stored — use the company's general contact or skip
    counsellor_wa = None

    return render_template(
        'student_portal.html',
        lead=lead,
        documents=documents,
        stage_states=stage_states,
        token=token,
        counsellor_wa=counsellor_wa
    )


@app.route('/portal/<token>/upload', methods=['POST'])
def portal_upload_document(token):
    """
    Student uploads a document link via their portal.
    Stored as a document record + triggers notification to counsellor.
    """
    doc_name = request.form.get('doc_name', '').strip()
    doc_link = request.form.get('doc_link', '').strip()

    if not doc_name or not doc_link:
        flash('Document name and link are required', 'error')
        return redirect(url_for('student_portal', token=token))

    # Resolve token
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM student_portals WHERE token = %s", (token,))
    portal = cursor.fetchone()
    release_db_connection(conn)

    if not portal:
        return render_template('portal_not_found.html'), 404

    company_id = portal['company_id']
    lead_id = portal['lead_id']

    conn2 = get_company_db(company_id)
    cursor2 = conn2.cursor()

    cursor2.execute(
        "SELECT name, assigned_user_id FROM leads WHERE id = %s AND company_id = %s",
        (lead_id, company_id)
    )
    lead = cursor2.fetchone()
    if not lead:
        release_db_connection(conn2)
        return render_template('portal_not_found.html'), 404

    # Save document
    cursor2.execute(
        "INSERT INTO documents (company_id, lead_id, document_name, document_link) VALUES (%s, %s, %s, %s)",
        (company_id, lead_id, doc_name, doc_link)
    )
    conn2.commit()
    release_db_connection(conn2)

    # ── TIER 4: Notify counsellor of student upload ───────────────────────
    if lead['assigned_user_id']:
        create_notification(
            company_id, lead['assigned_user_id'], 'portal_upload',
            f'📎 Document uploaded: {lead["name"]}',
            f'{lead["name"]} uploaded a document via the student portal: "{doc_name}". Check their profile.',
            lead_id=lead_id
        )

    flash('Document submitted successfully! Your counsellor will review it shortly. 😊', 'success')
    return redirect(url_for('student_portal', token=token))


# ============================================================================
# TIER 5 — OPTION 1: BULK LEAD REASSIGNMENT
# ============================================================================

@app.route('/leads/bulk-reassign', methods=['POST'])
@login_required
@super_admin_required
def bulk_reassign_leads():
    """Reassign multiple leads to a chosen counsellor in one action."""
    lead_ids_raw = request.form.getlist('lead_ids')
    new_user_id  = request.form.get('new_user_id', '').strip()

    if not lead_ids_raw or not new_user_id:
        flash('Please select at least one lead and a target counsellor.', 'error')
        return redirect(url_for('leads_list'))

    # Parse and deduplicate IDs safely
    try:
        lead_ids = list({int(x) for x in lead_ids_raw if x.strip().isdigit()})
    except ValueError:
        flash('Invalid lead selection.', 'error')
        return redirect(url_for('leads_list'))

    if not lead_ids:
        flash('No valid leads selected.', 'error')
        return redirect(url_for('leads_list'))

    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    # SECURITY: verify target user belongs to THIS company
    cursor.execute(
        "SELECT id, name FROM users WHERE id = %s AND company_id = %s",
        (new_user_id, session['company_id'])
    )
    target_user = cursor.fetchone()
    if not target_user:
        release_db_connection(conn)
        flash('Invalid counsellor selected.', 'error')
        return redirect(url_for('leads_list'))

    # SECURITY: UPDATE only touches leads WHERE company_id = session company
    cursor.execute("""
        UPDATE leads
        SET assigned_user_id = %s
        WHERE id = ANY(%s) AND company_id = %s
        RETURNING id, name
    """, (new_user_id, lead_ids, session['company_id']))
    updated = cursor.fetchall()

    # Audit log one entry per reassigned lead
    for lead in updated:
        cursor.execute(
            "INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
            (session['company_id'], session['user_id'],
             f'Bulk reassigned to {target_user["name"]}', lead['id'], request.remote_addr)
        )
        # Notification to newly assigned counsellor
        create_notification(
            session['company_id'], int(new_user_id), 'lead_assigned',
            f'Lead assigned to you: {lead["name"]}',
            f'{lead["name"]} was bulk-reassigned to you by {session["user_name"]}.',
            lead_id=lead['id']
        )

    conn.commit()
    release_db_connection(conn)

    flash(f'{len(updated)} lead(s) reassigned to {target_user["name"]} successfully.', 'success')
    return redirect(url_for('leads_list'))


# ============================================================================
# TIER 5 — OPTION 2: BULK DELETE STALE LEADS
# ============================================================================

@app.route('/leads/bulk-delete', methods=['POST'])
@login_required
@super_admin_required
def bulk_delete_leads():
    """Delete multiple leads at once (password-confirmed, stale leads page)."""
    lead_ids_raw = request.form.getlist('lead_ids')
    password     = request.form.get('password', '')

    if not lead_ids_raw:
        flash('No leads selected for deletion.', 'error')
        return redirect(url_for('stale_leads'))

    # Verify super admin password before any deletion
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash FROM users WHERE id = %s AND company_id = %s",
        (session['user_id'], session['company_id'])
    )
    admin = cursor.fetchone()
    if not admin or not check_password_hash(admin['password_hash'], password):
        release_db_connection(conn)
        flash('Incorrect password. No leads were deleted.', 'error')
        return redirect(url_for('stale_leads'))

    try:
        lead_ids = list({int(x) for x in lead_ids_raw if x.strip().isdigit()})
    except ValueError:
        release_db_connection(conn)
        flash('Invalid lead selection.', 'error')
        return redirect(url_for('stale_leads'))

    if not lead_ids:
        release_db_connection(conn)
        flash('No valid leads selected.', 'error')
        return redirect(url_for('stale_leads'))

    # SECURITY: fetch only leads that belong to THIS company before deleting
    cursor.execute(
        "SELECT id, name FROM leads WHERE id = ANY(%s) AND company_id = %s",
        (lead_ids, session['company_id'])
    )
    verified_leads = cursor.fetchall()
    verified_ids   = [l['id'] for l in verified_leads]

    if not verified_ids:
        release_db_connection(conn)
        flash('No matching leads found.', 'error')
        return redirect(url_for('stale_leads'))

    # Delete child records first (safety net even if ON DELETE CASCADE exists)
    cursor.execute("DELETE FROM interactions WHERE lead_id = ANY(%s) AND company_id = %s",
                   (verified_ids, session['company_id']))
    cursor.execute("DELETE FROM documents    WHERE lead_id = ANY(%s) AND company_id = %s",
                   (verified_ids, session['company_id']))
    cursor.execute("DELETE FROM followups    WHERE lead_id = ANY(%s) AND company_id = %s",
                   (verified_ids, session['company_id']))
    cursor.execute("DELETE FROM leads        WHERE id      = ANY(%s) AND company_id = %s",
                   (verified_ids, session['company_id']))

    # Single audit log entry for the bulk action
    names_summary = ', '.join(l['name'] for l in verified_leads[:5])
    if len(verified_leads) > 5:
        names_summary += f' … and {len(verified_leads) - 5} more'
    cursor.execute(
        "INSERT INTO audit_logs (company_id, user_id, action, lead_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
        (session['company_id'], session['user_id'],
         f'Bulk deleted {len(verified_ids)} leads: {names_summary}', None, request.remote_addr)
    )
    conn.commit()
    release_db_connection(conn)

    flash(f'{len(verified_ids)} lead(s) permanently deleted.', 'success')
    return redirect(url_for('stale_leads'))


# ============================================================================
# TIER 5 — OPTION 3: INCENTIVE TARGETS
# ============================================================================

def _get_tiers_for_target(target_id, company_id):
    """Return incentive tiers for a target, ordered by threshold ascending."""
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM incentive_tiers
        WHERE target_id = %s AND company_id = %s
        ORDER BY threshold_percent ASC
    """, (target_id, company_id))
    tiers = cursor.fetchall()
    release_db_connection(conn)
    return tiers


def _calc_user_incentive(user_id, company_id, target, tiers):
    """
    Calculate registrations, won deals, percentage achieved, and
    the highest incentive tier unlocked for a single user.
    Returns a dict.
    """
    conn = get_company_db(company_id)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            COUNT(CASE WHEN lead_status = 'Registered'  THEN 1 END) AS registrations,
            COUNT(CASE WHEN lead_status = 'Closed - Won' THEN 1 END) AS won
        FROM leads
        WHERE company_id = %s
          AND assigned_user_id = %s
          AND created_at::DATE BETWEEN %s AND %s
    """, (company_id, user_id, target['period_start'], target['period_end']))
    row = cursor.fetchone()
    release_db_connection(conn)

    registrations = row['registrations'] or 0
    won           = row['won'] or 0

    # Percentage achieved — use the higher of the two targets as the anchor
    reg_pct = (registrations / target['registration_target'] * 100) if target['registration_target'] > 0 else 100
    won_pct = (won / target['won_target'] * 100) if target['won_target'] > 0 else 100
    # Overall % = average of both dimensions (or whichever is applicable)
    overall_pct = (reg_pct + won_pct) / 2

    # Find highest tier unlocked
    earned_tier   = None
    earned_amount = 0.0
    for tier in sorted(tiers, key=lambda t: t['threshold_percent']):
        if overall_pct >= tier['threshold_percent']:
            earned_tier   = tier
            earned_amount = float(tier['incentive_amount'])

    return {
        'registrations': registrations,
        'won': won,
        'reg_pct': round(reg_pct, 1),
        'won_pct': round(won_pct, 1),
        'overall_pct': round(overall_pct, 1),
        'earned_tier': earned_tier,
        'earned_amount': earned_amount,
    }


@app.route('/incentives', methods=['GET', 'POST'])
@login_required
@super_admin_required
def incentive_targets():
    """Super admin: create / manage incentive targets and tiers."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    if request.method == 'POST':
        action = request.form.get('action', '')

        # ── Create new target ──────────────────────────────────────────────
        if action == 'create_target':
            period_type          = request.form.get('period_type', 'monthly')
            period_start         = request.form.get('period_start', '').strip()
            period_end           = request.form.get('period_end', '').strip()
            registration_target  = request.form.get('registration_target', 0)
            won_target           = request.form.get('won_target', 0)
            label                = request.form.get('label', '').strip()

            if not period_start or not period_end:
                release_db_connection(conn)
                flash('Start and end dates are required.', 'error')
                return redirect(url_for('incentive_targets'))

            # Deactivate all previous targets for this company
            cursor.execute(
                "UPDATE incentive_targets SET is_active = FALSE WHERE company_id = %s",
                (session['company_id'],)
            )
            cursor.execute("""
                INSERT INTO incentive_targets
                    (company_id, period_type, period_start, period_end,
                     registration_target, won_target, label, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (session['company_id'], period_type, period_start, period_end,
                  int(registration_target or 0), int(won_target or 0),
                  label or None, session['user_id']))
            new_target_id = cursor.fetchone()['id']
            conn.commit()

            # Parse tiers submitted alongside the target
            tier_labels   = request.form.getlist('tier_label')
            tier_pcts     = request.form.getlist('tier_threshold')
            tier_amounts  = request.form.getlist('tier_amount')
            for lbl, pct, amt in zip(tier_labels, tier_pcts, tier_amounts):
                lbl = lbl.strip(); pct = pct.strip(); amt = amt.strip()
                if lbl and pct and amt:
                    try:
                        cursor.execute("""
                            INSERT INTO incentive_tiers
                                (target_id, company_id, tier_label, threshold_percent, incentive_amount)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (new_target_id, session['company_id'],
                              lbl, int(pct), float(amt)))
                    except (ValueError, TypeError):
                        pass
            conn.commit()
            release_db_connection(conn)
            flash('Incentive target created successfully.', 'success')
            return redirect(url_for('incentive_targets'))

        # ── Deactivate target ──────────────────────────────────────────────
        elif action == 'deactivate':
            target_id = request.form.get('target_id', '')
            cursor.execute(
                "UPDATE incentive_targets SET is_active = FALSE WHERE id = %s AND company_id = %s",
                (target_id, session['company_id'])
            )
            conn.commit()
            release_db_connection(conn)
            flash('Target deactivated.', 'success')
            return redirect(url_for('incentive_targets'))

        # ── Delete target ──────────────────────────────────────────────────
        elif action == 'delete_target':
            target_id = request.form.get('target_id', '')
            cursor.execute(
                "DELETE FROM incentive_targets WHERE id = %s AND company_id = %s",
                (target_id, session['company_id'])
            )
            conn.commit()
            release_db_connection(conn)
            flash('Target deleted.', 'success')
            return redirect(url_for('incentive_targets'))

        release_db_connection(conn)
        return redirect(url_for('incentive_targets'))

    # GET — load all targets for this company
    cursor.execute("""
        SELECT t.*, u.name as created_by_name
        FROM incentive_targets t
        LEFT JOIN users u ON t.created_by = u.id
        WHERE t.company_id = %s
        ORDER BY t.created_at DESC
    """, (session['company_id'],))
    all_targets = cursor.fetchall()

    # Load tiers and user progress for each target
    targets_data = []
    for target in all_targets:
        tiers = _get_tiers_for_target(target['id'], session['company_id'])

        # Load all counsellors
        cursor.execute(
            "SELECT id, name FROM users WHERE company_id = %s AND role = 'user' ORDER BY name",
            (session['company_id'],)
        )
        counsellors = cursor.fetchall()

        user_progress = []
        for c in counsellors:
            prog = _calc_user_incentive(c['id'], session['company_id'], target, tiers)
            prog['name']    = c['name']
            prog['user_id'] = c['id']
            user_progress.append(prog)

        # Sort by overall_pct descending
        user_progress.sort(key=lambda x: x['overall_pct'], reverse=True)

        targets_data.append({
            'target':        dict(target),
            'tiers':         [dict(t) for t in tiers],
            'user_progress': user_progress,
        })

    release_db_connection(conn)
    return render_template('incentive_targets.html',
                           targets_data=targets_data)


@app.route('/my-incentives')
@login_required
def my_incentives():
    """Counsellor view: personal incentive progress and earnings."""
    conn = get_company_db(session['company_id'])
    cursor = conn.cursor()

    # Load all targets for this company (active first)
    cursor.execute("""
        SELECT * FROM incentive_targets
        WHERE company_id = %s
        ORDER BY is_active DESC, created_at DESC
    """, (session['company_id'],))
    all_targets = cursor.fetchall()

    # Load peers for comparison (all counsellors)
    cursor.execute(
        "SELECT id, name FROM users WHERE company_id = %s AND role = 'user' ORDER BY name",
        (session['company_id'],)
    )
    counsellors = cursor.fetchall()
    release_db_connection(conn)

    my_targets = []
    for target in all_targets:
        tiers = _get_tiers_for_target(target['id'], session['company_id'])
        my_prog = _calc_user_incentive(session['user_id'], session['company_id'], target, tiers)

        # Peer comparison for this target
        peer_progress = []
        for c in counsellors:
            prog = _calc_user_incentive(c['id'], session['company_id'], target, tiers)
            prog['name']    = c['name']
            prog['user_id'] = c['id']
            prog['is_me']   = (c['id'] == session['user_id'])
            peer_progress.append(prog)
        peer_progress.sort(key=lambda x: x['overall_pct'], reverse=True)

        my_targets.append({
            'target':        dict(target),
            'tiers':         [dict(t) for t in tiers],
            'my_progress':   my_prog,
            'peer_progress': peer_progress,
        })

    return render_template('my_incentives.html',
                           my_targets=my_targets)


# ============================================================================
# STARTUP — runs once on module load (gunicorn workers and local dev)
# ============================================================================
try:
    init_connection_pool()
    init_master_db()
    init_company_db(None)
    migrate_databases()
    migrate_indexes()
    print("✅ Application startup complete")
except Exception as e:
    print(f"❌ Startup error: {e}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
    
