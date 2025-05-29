import os
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, abort, send_file
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask_session import Session
import sqlite3
from datetime import datetime, timedelta
import secrets
import logging
import getpass
from dotenv import load_dotenv
import qrcode
from PIL import Image
import uuid
import pandas as pd
from io import BytesIO
from werkzeug.utils import secure_filename
import base64
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
Session(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# Configuration from .env
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000")
DB_PATH = os.getenv("DB_PATH", "regoffice.db")
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "static/uploads")
ALLOWED_EXTENSIONS = {'mp4', 'jpg', 'jpeg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    filename=os.getenv("LOG_FILE", "app.log"),
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    """Initialize the SQLite database and create tables if they don't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Categories with color support
        c.execute('''CREATE TABLE IF NOT EXISTS categories (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     name TEXT NOT NULL,
                     parent_id INTEGER,
                     color TEXT DEFAULT '#FFFFFF',
                     FOREIGN KEY(parent_id) REFERENCES categories(id))''')
        # Services with color support
        c.execute('''CREATE TABLE IF NOT EXISTS services (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     name TEXT NOT NULL,
                     category_id INTEGER NOT NULL,
                     color TEXT DEFAULT '#FFFFFF',
                     FOREIGN KEY(category_id) REFERENCES categories(id))''')
        # Operators
        c.execute('''CREATE TABLE IF NOT EXISTS operators (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     name TEXT NOT NULL,
                     hashed_password TEXT NOT NULL,
                     status TEXT DEFAULT 'active',
                     operator_number INTEGER UNIQUE)''')
        # Operator-Service mappings
        c.execute('''CREATE TABLE IF NOT EXISTS operator_services (
                     operator_id INTEGER,
                     service_id INTEGER,
                     PRIMARY KEY (operator_id, service_id),
                     FOREIGN KEY(operator_id) REFERENCES operators(id) ON DELETE CASCADE,
                     FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE)''')
        # Tickets
        c.execute('''CREATE TABLE IF NOT EXISTS tickets (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     number TEXT NOT NULL UNIQUE,
                     service_id INTEGER NOT NULL,
                     status TEXT NOT NULL,
                     operator_id INTEGER,
                     created_at TEXT NOT NULL,
                     finished_at TEXT,
                     kiosk_id INTEGER NOT NULL,
                     FOREIGN KEY(service_id) REFERENCES services(id),
                     FOREIGN KEY(operator_id) REFERENCES operators(id))''')
        # Messages
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     operator_id INTEGER,
                     content TEXT NOT NULL,
                     timestamp TEXT NOT NULL,
                     FOREIGN KEY(operator_id) REFERENCES operators(id))''')
        # Admin users
        c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE NOT NULL,
                     hashed_password TEXT NOT NULL)''')
        # Evaluations
        c.execute('''CREATE TABLE IF NOT EXISTS evaluations (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ticket_number TEXT NOT NULL,
                     operator_id INTEGER,
                     rating INTEGER CHECK(rating >= 1 AND rating <= 5),
                     comment TEXT,
                     created_at TEXT NOT NULL,
                     FOREIGN KEY(ticket_number) REFERENCES tickets(number),
                     FOREIGN KEY(operator_id) REFERENCES operators(id))''')
        # Disputes
        c.execute('''CREATE TABLE IF NOT EXISTS disputes (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ticket_number TEXT NOT NULL,
                     operator_id INTEGER,
                     comment TEXT NOT NULL,
                     created_at TEXT NOT NULL,
                     status TEXT NOT NULL,
                     FOREIGN KEY(ticket_number) REFERENCES tickets(number),
                     FOREIGN KEY(operator_id) REFERENCES operators(id))''')
        # Chats
        c.execute('''CREATE TABLE IF NOT EXISTS chats (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ticket_number TEXT NOT NULL,
                     sender_type TEXT NOT NULL,
                     sender_id INTEGER,
                     content TEXT NOT NULL,
                     timestamp TEXT NOT NULL,
                     FOREIGN KEY(ticket_number) REFERENCES tickets(number))''')
        # Media
        c.execute('''CREATE TABLE IF NOT EXISTS media (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     type TEXT NOT NULL CHECK(type IN ('image', 'video')),
                     filename TEXT NOT NULL UNIQUE,
                     original_filename TEXT,
                     title TEXT,
                     description TEXT,
                     display_order INTEGER DEFAULT 0,
                     is_active INTEGER DEFAULT 0,
                     duration INTEGER,
                     created_at TEXT NOT NULL,
                     uploaded_by INTEGER,
                     FOREIGN KEY(uploaded_by) REFERENCES admin_users(id))''')

        # Create default admin user if none exists
        c.execute("SELECT COUNT(*) FROM admin_users")
        if c.fetchone()[0] == 0:
            username = input("Enter admin username: ")
            password = getpass.getpass("Enter admin password: ")
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            c.execute("INSERT INTO admin_users (username, hashed_password) VALUES (?, ?)",
                      (username, hashed_password))
            logging.info(f"Created admin user: {username}")

        # Ensure indexes for performance
        c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_created_at ON tickets(created_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_service_id ON tickets(service_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_operator_id ON tickets(operator_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_media_is_active ON media(is_active)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_media_display_order ON media(display_order)")

        conn.commit()

# Decorators
def login_required(f):
    """Require operator login for protected routes."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'operator_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Require admin login for protected routes."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def get_category_depth(category_id):
    """Calculate the depth of a category in the hierarchy."""
    if not category_id:
        return 0
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        depth = 0
        current_id = category_id
        while current_id:
            c.execute("SELECT parent_id FROM categories WHERE id = ?", (current_id,))
            result = c.fetchone()
            if not result or not result[0]:
                break
            current_id = result[0]
            depth += 1
            if depth >= 10:  # Prevent infinite loops
                return 10
        return depth

# Routes
@app.route('/')
def index():
    """Render the main kiosk interface."""
    return render_template('index.html', server_url=SERVER_URL)

@app.route('/categories', methods=['GET'])
def get_categories():
    """Fetch top-level categories with colors."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, color FROM categories WHERE parent_id IS NULL ORDER BY name")
        categories = [{"id": row[0], "name": row[1], "type": "category", "color": row[2]} for row in c.fetchall()]
        logging.info(f"Fetched {len(categories)} top-level categories")
        return jsonify(categories)

@app.route('/services/<int:category_id>', methods=['GET'])
def get_services(category_id):
    """Fetch services and subcategories for a given category, including nested subcategories."""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Fetch subcategories
        c.execute("SELECT id, name, color FROM categories WHERE parent_id = ? ORDER BY name LIMIT ? OFFSET ?",
                  (category_id, per_page, offset))
        subcategories = [{"id": row[0], "name": row[1], "type": "subcategory", "color": row[2]} for row in c.fetchall()]
        c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ?", (category_id,))
        total_subcategories = c.fetchone()[0]
        # Fetch services
        c.execute("SELECT id, name, color FROM services WHERE category_id = ? ORDER BY name LIMIT ? OFFSET ?",
                  (category_id, per_page, offset))
        services = [{"id": row[0], "name": row[1], "type": "service", "color": row[2]} for row in c.fetchall()]
        c.execute("SELECT COUNT(*) FROM services WHERE category_id = ?", (category_id,))
        total_services = c.fetchone()[0]
        # Fetch nested subcategory tree
        def get_subcategory_tree(cat_id):
            c.execute("SELECT id, name, color FROM categories WHERE parent_id = ? ORDER BY name", (cat_id,))
            subs = [{"id": row[0], "name": row[1], "type": "subcategory", "color": row[2],
                     "subcategories": get_subcategory_tree(row[0])} for row in c.fetchall()]
            return subs
        subcategory_tree = get_subcategory_tree(category_id)
        items = subcategories + services
        total = total_subcategories + total_services
        logging.info(f"Fetched {len(items)} items for category {category_id}, page {page}")
        return jsonify({
            "items": items,
            "subcategory_tree": subcategory_tree,
            "total": total,
            "page": page,
            "per_page": per_page
        })

@app.route('/get_ticket', methods=['POST'])
def get_ticket():
    """Generate a new ticket for a service."""
    data = request.get_json() or {}
    service_id = data.get('service_id', type=int)
    lang = data.get('lang', 'uz_lat')
    kiosk_id = data.get('kiosk_id', 1, type=int)
    if not service_id:
        return jsonify({"error": "Service ID is required"}), 400
    logging.info(f"Requesting ticket: service_id={service_id}, lang={lang}, kiosk_id={kiosk_id}")
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT name, category_id FROM services WHERE id = ?", (service_id,))
        service = c.fetchone()
        if not service:
            logging.error(f"Service {service_id} not found")
            return jsonify({"error": "Service not found"}), 404
        service_name = service[0]
        # Generate ticket number
        c.execute("SELECT COUNT(*) FROM tickets WHERE service_id = ? AND DATE(created_at) = DATE('now')",
                  (service_id,))
        count = c.fetchone()[0] + 1
        ticket_number = f"{service_id:02d}-{count:03d}"
        # Estimate wait time
        c.execute("SELECT AVG(strftime('%s', finished_at) - strftime('%s', created_at)) / 60.0 "
                  "FROM tickets WHERE service_id = ? AND finished_at IS NOT NULL", (service_id,))
        avg_time = c.fetchone()[0] or 5.0
        wait_time = round(avg_time * count)
        # Assign operator
        c.execute("SELECT operator_id FROM operator_services WHERE service_id = ? LIMIT 1", (service_id,))
        operator = c.fetchone()
        operator_id = operator[0] if operator else None
        operator_name = None
        operator_number = None
        if operator_id:
            c.execute("SELECT name, operator_number FROM operators WHERE id = ?", (operator_id,))
            op_data = c.fetchone()
            if op_data:
                operator_name = op_data[0]
                operator_number = op_data[1]
        created_at = datetime.now().isoformat()
        c.execute("INSERT INTO tickets (number, service_id, status, operator_id, created_at, kiosk_id) "
                  "VALUES (?, ?, 'waiting', ?, ?, ?)",
                  (ticket_number, service_id, operator_id, created_at, kiosk_id))
        ticket_id = c.lastrowid
        conn.commit()
        # Generate QR code
        status_url = f"{SERVER_URL}/ticket/{ticket_number}"
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(status_url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_data = base64.b64encode(buffered.getvalue()).decode('utf-8')
        socketio.emit('new_ticket', {'ticket': ticket_number, 'service_id': service_id, 'operator_id': operator_id})
        logging.info(f"Created ticket: {ticket_number}, service_id: {service_id}, operator_id: {operator_id or 'None'}")
        return jsonify({
            "ticket": ticket_number,
            "ticket_id": ticket_id,
            "wait_time": wait_time,
            "service_name": service_name,
            "operator_id": operator_id,
            "operator_name": operator_name,
            "operator_number": operator_number,
            "created_at": created_at,
            "status_url": status_url,
            "qr_data": qr_data
        })

@app.route('/print_ticket', methods=['POST'])
def print_ticket():
    """Generate HTML for browser-based ticket printing."""
    data = request.get_json() or {}
    ticket_number = data.get('ticket_number')
    if not ticket_number:
        return jsonify({"error": "Ticket number is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT t.number, t.created_at, s.name, o.name, o.operator_number
            FROM tickets t
            LEFT JOIN services s ON t.service_id = s.id
            LEFT JOIN operators o ON t.operator_id = o.id
            WHERE t.number = ?
        """, (ticket_number,))
        ticket = c.fetchone()
        if not ticket:
            logging.error(f"Ticket {ticket_number} not found for printing")
            return jsonify({"error": "Ticket not found"}), 404
        ticket_data = {
            "number": ticket[0],
            "created_at": ticket[1],
            "service_name": ticket[2],
            "operator_name": ticket[3],
            "operator_number": ticket[4]
        }
        return render_template('print_ticket.html', ticket=ticket_data, server_url=SERVER_URL)

@app.route('/ticket_status/<ticket_number>', methods=['GET'])
def ticket_status():
    """Get the status of a specific ticket."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT t.id, t.number, t.service_id, t.status, t.operator_id, t.created_at,
                   s.name AS service_name, o.name AS operator_name, o.operator_number
            FROM tickets t
            LEFT JOIN services s ON t.service_id = s.id
            LEFT JOIN operators o ON t.operator_id = o.id
            WHERE t.number = ?
        """, (ticket_number,))
        ticket = c.fetchone()
        if not ticket:
            logging.error(f"Ticket {ticket_number} not found")
            return jsonify({"error": "Ticket not found"}), 404
        c.execute("""
            SELECT COUNT(*) FROM tickets
            WHERE service_id = ? AND status = 'waiting' AND created_at <= ?
        """, (ticket[2], ticket[5]))
        position = c.fetchone()[0] if ticket[3] == 'waiting' else 0
        c.execute("""
            SELECT AVG(strftime('%s', finished_at) - strftime('%s', created_at)) / 60.0
            FROM tickets WHERE service_id = ? AND finished_at IS NOT NULL
        """, (ticket[2],))
        avg_time = c.fetchone()[0] or 5.0
        wait_time = round(avg_time * position) if position > 0 else 0
        return jsonify({
            "ticket_id": ticket[0],
            "ticket_number": ticket[1],
            "service_name": ticket[6],
            "status": ticket[3],
            "operator_name": ticket[7],
            "operator_number": ticket[8],
            "position": position,
            "wait_time": wait_time
        })

@app.route('/ticket/<ticket_number>')
def ticket_page():
    """Render the ticket status page."""
    return render_template('ticket_status.html', ticket_number=ticket_number, server_url=SERVER_URL)

@app.route('/dispute/<ticket_number>', methods=['GET', 'POST'])
def dispute():
    """Handle dispute filing for a ticket."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, operator_id FROM tickets WHERE number = ?", (ticket_number,))
        ticket = c.fetchone()
        if not ticket:
            return render_template('error.html', message="Ticket not found", server_url=SERVER_URL), 404
        if request.method == 'POST':
            comment = request.form.get('comment')
            if not comment:
                return render_template('dispute.html', ticket_number=ticket_number,
                                       error="Comment is required", server_url=SERVER_URL), 400
            created_at = datetime.now().isoformat()
            c.execute("INSERT INTO disputes (ticket_number, operator_id, comment, created_at, status) "
                      "VALUES (?, ?, ?, ?, 'open')",
                      (ticket_number, ticket[1], comment, created_at))
            conn.commit()
            logging.info(f"Dispute filed for ticket {ticket_number}")
            return redirect(url_for('ticket_page', ticket_number=ticket_number))
        return render_template('dispute.html', ticket_number=ticket_number, server_url=SERVER_URL)

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    """Submit feedback for a ticket."""
    ticket_id = request.form.get('ticket_id', type=int)
    rating = request.form.get('rating', type=int)
    comment = request.form.get('comment')
    if not ticket_id or not rating or rating < 1 or rating > 5:
        return jsonify({"error": "Valid ticket ID and rating (1-5) are required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT number, operator_id FROM tickets WHERE id = ?", (ticket_id,))
        ticket = c.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        ticket_number, operator_id = ticket
        created_at = datetime.now().isoformat()
        c.execute("INSERT INTO evaluations (ticket_number, operator_id, rating, comment, created_at) "
                  "VALUES (?, ?, ?, ?, ?)",
                  (ticket_number, operator_id, rating, comment, created_at))
        conn.commit()
        logging.info(f"Feedback submitted for ticket {ticket_number}: rating={rating}")
        return redirect(url_for('ticket_page', ticket_number=ticket_number))

@app.route('/chat/<ticket_number>')
def chat():
    """Render the chat interface for a ticket."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM tickets WHERE number = ?", (ticket_number,))
        ticket = c.fetchone()
        if not ticket:
            return render_template('error.html', message="Invalid ticket", server_url=SERVER_URL), 404
        return render_template('chat.html', ticket_id=ticket[0], ticket_number=ticket_number,
                               server_url=SERVER_URL)

@app.route('/api/admin/statistics/data', methods=['GET'])
@admin_required
def statistics_data():
    """Fetch detailed statistics for services, categories, or operators."""
    view_type = request.args.get('view_type')  # 'service', 'category', 'operator_overall', 'operator_individual'
    service_id = request.args.get('service_id', type=int)
    category_id = request.args.get('category_id', type=int)
    operator_id = request.args.get('operator_id', type=int)
    time_filter = request.args.get('time_filter')  # 'daily', 'monthly', 'half_yearly', 'yearly', 'custom'
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if time_filter == 'custom' and (not start_date or not end_date):
        return jsonify({"status": "error", "message": "Custom date range requires start_date and end_date"}), 400

    # Determine date range
    if time_filter != 'custom':
        end_date = datetime.now().isoformat()
        if time_filter == 'daily':
            start_date = (datetime.now() - timedelta(days=1)).isoformat()
        elif time_filter == 'monthly':
            start_date = (datetime.now() - timedelta(days=30)).isoformat()
        elif time_filter == 'half_yearly':
            start_date = (datetime.now() - timedelta(days=180)).isoformat()
        elif time_filter == 'yearly':
            start_date = (datetime.now() - timedelta(days=365)).isoformat()
        else:
            return jsonify({"status": "error", "message": "Invalid time filter"}), 400

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Base query for table data
        query = """
            SELECT
                t.number,
                s.name AS service_name,
                c.name AS category_name,
                o.name AS operator_name,
                o.operator_number,
                t.status,
                t.created_at,
                t.finished_at,
                (strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0 AS service_time
            FROM tickets t
            JOIN services s ON t.service_id = s.id
            JOIN categories c ON s.category_id = c.id
            LEFT JOIN operators o ON t.operator_id = o.id
            WHERE t.created_at BETWEEN ? AND ?
        """
        params = [start_date, end_date]
        if service_id:
            query += " AND t.service_id = ?"
            params.append(service_id)
        if category_id:
            query += " AND s.category_id = ?"
            params.append(category_id)
        if operator_id and view_type == 'operator_individual':
            query += " AND t.operator_id = ?"
            params.append(operator_id)

        c.execute(query, params)
        df = pd.DataFrame(c.fetchall(), columns=[
            'Ticket Number', 'Service Name', 'Category Name', 'Operator Name',
            'Operator Number', 'Status', 'Created At', 'Finished At', 'Service Time'
        ])

        # Chart data based on view_type
        chart_data = []
        group_time = {
            'daily': "strftime('%Y-%m-%d', t.created_at)",
            'monthly': "strftime('%Y-%m', t.created_at)",
            'half_yearly': "strftime('%Y-' || (CASE WHEN strftime('%m', t.created_at) <= '06' THEN 'H1' ELSE 'H2' END), t.created_at)",
            'yearly': "strftime('%Y', t.created_at)"
        }.get(time_filter, "strftime('%Y-%m', t.created_at)")

        if view_type == 'service' and service_id:
            c.execute(f"""
                SELECT
                    {group_time} AS time_period,
                    s.name AS service_name,
                    c.name AS category_name,
                    COUNT(t.id) AS ticket_count,
                    AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time
                FROM tickets t
                JOIN services s ON t.service_id = s.id
                JOIN categories c ON s.category_id = c.id
                WHERE t.created_at BETWEEN ? AND ? AND t.service_id = ?
                GROUP BY time_period, s.id
            """, (start_date, end_date, service_id))
            chart_data = c.fetchall()
        elif view_type == 'category' and category_id:
            c.execute(f"""
                SELECT
                    {group_time} AS time_period,
                    c.name AS category_name,
                    COUNT(t.id) AS ticket_count,
                    AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time
                FROM tickets t
                JOIN services s ON t.service_id = s.id
                JOIN categories c ON s.category_id = c.id
                WHERE t.created_at BETWEEN ? AND ? AND s.category_id = ?
                GROUP BY time_period, c.id
            """, (start_date, end_date, category_id))
            chart_data = c.fetchall()
        elif view_type == 'operator_overall':
            c.execute(f"""
                SELECT
                    {group_time} AS time_period,
                    o.name AS operator_name,
                    o.operator_number,
                    COUNT(t.id) AS ticket_count,
                    AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time
                FROM tickets t
                LEFT JOIN operators o ON t.operator_id = o.id
                WHERE t.created_at BETWEEN ? AND ?
                GROUP BY time_period, o.id
            """, (start_date, end_date))
            chart_data = c.fetchall()
        elif view_type == 'operator_individual' and operator_id and service_id:
            c.execute(f"""
                SELECT
                    {group_time} AS time_period,
                    s.name AS service_name,
                    COUNT(t.id) AS ticket_count,
                    AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time
                FROM tickets t
                JOIN services s ON t.service_id = s.id
                WHERE t.created_at BETWEEN ? AND ? AND t.operator_id = ? AND t.service_id = ?
                GROUP BY time_period, s.id
            """, (start_date, end_date, operator_id, service_id))
            chart_data = c.fetchall()

        return jsonify({
            "table_data": df.to_dict(orient='records'),
            "chart_data": [{
                "time_period": row[0],
                "name": row[1],
                "ticket_count": row[3] if len(row) > 3 else row[2],
                "avg_service_time": row[4] if len(row) > 4 else row[3]
            } for row in chart_data]
        })

@app.route('/api/admin/statistics/export', methods=['POST'])
@admin_required
def export_statistics():
    """Export statistics to an Excel file."""
    data = request.get_json() or {}
    view_type = data.get('view_type')
    service_id = data.get('service_id', type=int)
    category_id = data.get('category_id', type=int)
    operator_id = data.get('operator_id', type=int)
    time_filter = data.get('time_filter')
    start_date = data.get('start_date')
    end_date = data.get('end_date')

    if time_filter == 'custom' and (not start_date or not end_date):
        return jsonify({"status": "error", "message": "Custom date range requires start_date and end_date"}), 400

    if time_filter != 'custom':
        end_date = datetime.now()
        if time_filter == 'daily':
            start_date = end_date - timedelta(days=1)
        elif time_filter == 'monthly':
            start_date = end_date - timedelta(days=30)
        elif time_filter == 'half_yearly':
            start_date = end_date - timedelta(days=180)
        elif time_filter == 'yearly':
            start_date = end_date - timedelta(days=365)
        start_date = start_date.isoformat()
        end_date = end_date.isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        query = """
            SELECT
                t.number,
                s.name AS service_name,
                c.name AS category_name,
                o.name AS operator_name,
                o.operator_number,
                t.status,
                t.created_at,
                t.finished_at,
                (strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0 AS service_time
            FROM tickets t
            JOIN services s ON t.service_id = s.id
            JOIN categories c ON s.category_id = c.id
            LEFT JOIN operators o ON t.operator_id = o.id
            WHERE t.created_at BETWEEN ? AND ?
        """
        params = [start_date, end_date]
        if service_id:
            query += " AND t.service_id = ?"
            params.append(service_id)
        if category_id:
            query += " AND s.category_id = ?"
            params.append(category_id)
        if operator_id and view_type == 'operator_individual':
            query += " AND t.operator_id = ?"
            params.append(operator_id)

        c.execute(query, params)
        df = pd.DataFrame(c.fetchall(), columns=[
            'Ticket Number', 'Service Name', 'Category Name', 'Operator Name',
            'Operator Number', 'Status', 'Created At', 'Finished At', 'Service Time'
        ])

        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Summary', index=False)
            group_time = {
                'daily': "strftime('%Y-%m-%d', t.created_at)",
                'monthly': "strftime('%Y-%m', t.created_at)",
                'half_yearly': "strftime('%Y-' || (CASE WHEN strftime('%m', t.created_at) <= '06' THEN 'H1' ELSE 'H2' END), t.created_at)",
                'yearly': "strftime('%Y', t.created_at)"
            }.get(time_filter, "strftime('%Y-%m', t.created_at)")

            if view_type == 'service':
                c.execute(f"""
                    SELECT
                        {group_time} AS time_period,
                        s.name AS service_name,
                        c.name AS category_name,
                        COUNT(t.id) AS ticket_count,
                        AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time
                    FROM tickets t
                    JOIN services s ON t.service_id = s.id
                    JOIN categories c ON s.category_id = c.id
                    WHERE t.created_at BETWEEN ? AND ?
                    GROUP BY time_period, s.id
                """, (start_date, end_date))
                service_df = pd.DataFrame(c.fetchall(), columns=[
                    'Time Period', 'Service Name', 'Category Name', 'Ticket Count', 'Avg Service Time'
                ])
                service_df.to_excel(writer, sheet_name='Service Stats', index=False)
            elif view_type == 'category':
                c.execute(f"""
                    SELECT
                        {group_time} AS time_period,
                        c.name AS category_name,
                        COUNT(t.id) AS ticket_count,
                        AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time
                    FROM tickets t
                    JOIN services s ON t.service_id = s.id
                    JOIN categories c ON s.category_id = c.id
                    WHERE t.created_at BETWEEN ? AND ?
                    GROUP BY time_period, c.id
                """, (start_date, end_date))
                category_df = pd.DataFrame(c.fetchall(), columns=[
                    'Time Period', 'Category Name', 'Ticket Count', 'Avg Service Time'
                ])
                category_df.to_excel(writer, sheet_name='Category Stats', index=False)
            elif view_type == 'operator_overall':
                c.execute(f"""
                    SELECT
                        {group_time} AS time_period,
                        o.name AS operator_name,
                        o.operator_number,
                        COUNT(t.id) AS ticket_count,
                        AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time
                    FROM tickets t
                    LEFT JOIN operators o ON t.operator_id = o.id
                    WHERE t.created_at BETWEEN ? AND ?
                    GROUP BY time_period, o.id
                """, (start_date, end_date))
                operator_df = pd.DataFrame(c.fetchall(), columns=[
                    'Time Period', 'Operator Name', 'Operator Number', 'Ticket Count', 'Avg Service Time'
                ])
                operator_df.to_excel(writer, sheet_name='Operator Stats', index=False)

        output.seek(0)
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'statistics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        )

@app.route('/api/admin/recommendations', methods=['GET'])
@admin_required
def recommendations():
    """Generate recommendations based on performance analytics."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Problematic services
        c.execute("""
            SELECT
                s.name,
                c.name AS category_name,
                AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time,
                COUNT(d.id) AS dispute_count,
                COUNT(t.id) AS ticket_count
            FROM tickets t
            JOIN services s ON t.service_id = s.id
            JOIN categories c ON s.category_id = c.id
            LEFT JOIN disputes d ON t.number = d.ticket_number
            WHERE t.finished_at IS NOT NULL
            GROUP BY s.id
            HAVING avg_service_time > 10 OR dispute_count > 0
        """)
        problem_services = [{
            "service_name": row[0],
            "category_name": row[1],
            "avg_service_time": row[2],
            "dispute_count": row[3],
            "ticket_count": row[4]
        } for row in c.fetchall()]

        # Problematic categories
        c.execute("""
            SELECT
                c.name,
                AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time,
                COUNT(t.id) AS ticket_count
            FROM tickets t
            JOIN services s ON t.service_id = s.id
            JOIN categories c ON s.category_id = c.id
            WHERE t.finished_at IS NOT NULL
            GROUP BY c.id
            HAVING avg_service_time > 15
        """)
        problem_categories = [{
            "category_name": row[0],
            "avg_service_time": row[1],
            "ticket_count": row[2]
        } for row in c.fetchall()]

        # Problematic operators
        c.execute("""
            SELECT
                o.name,
                o.operator_number,
                AVG(e.rating) AS avg_rating,
                COUNT(d.id) AS dispute_count,
                COUNT(t.id) AS ticket_count,
                AVG((strftime('%s', t.finished_at) - strftime('%s', t.created_at)) / 60.0) AS avg_service_time
            FROM operators o
            LEFT JOIN evaluations e ON e.operator_id = o.id
            LEFT JOIN disputes d ON d.operator_id = o.id
            LEFT JOIN tickets t ON t.operator_id = o.id AND t.finished_at IS NOT NULL
            GROUP BY o.id
            HAVING avg_rating < 3 OR dispute_count > 0 OR avg_service_time > 15
        """)
        problem_operators = [{
            "name": row[0],
            "operator_number": row[1],
            "avg_rating": row[2],
            "dispute_count": row[3],
            "ticket_count": row[4],
            "avg_service_time": row[5]
        } for row in c.fetchall()]

        recommendations = []
        recommendations.extend([
            {
                "type": "service",
                "message": f"Service '{s['service_name']}' in category '{s['category_name']}' has high service time "
                           f"({s['avg_service_time']:.1f} min) or disputes ({s['dispute_count']}). "
                           "Consider adding operators or optimizing the process."
            } for s in problem_services
        ])
        recommendations.extend([
            {
                "type": "category",
                "message": f"Category '{c['category_name']}' has high average service time "
                           f"({c['avg_service_time']:.1f} min). Review service distribution."
            } for c in problem_categories
        ])
        recommendations.extend([
            {
                "type": "operator",
                "message": f"Operator '{o['name']}' (#{o['operator_number'] or 'N/A'}) has low rating "
                           f"({o['avg_rating']:.1f}), high service time ({o['avg_service_time']:.1f} min), "
                           f"or disputes ({o['dispute_count']}). Consider training or reassignment."
            } for o in problem_operators if o['avg_rating'] or o['dispute_count'] or o['avg_service_time']
        ])

        return jsonify({
            "problem_services": problem_services,
            "problem_categories": problem_categories,
            "problem_operators": problem_operators,
            "recommendations": recommendations
        })

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    """Handle admin login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('admin_login.html', error="Username and password are required",
                                   server_url=SERVER_URL), 400
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT id, hashed_password FROM admin_users WHERE username = ?", (username,))
            admin = c.fetchone()
            if admin and check_password_hash(admin[1], password):
                session['admin_id'] = admin[0]
                logging.info(f"Admin {username} logged in")
                return redirect(url_for('admin'))
            logging.warning(f"Failed admin login attempt for {username}")
            return render_template('admin_login.html', error="Invalid credentials",
                                   server_url=SERVER_URL), 401
    return render_template('admin_login.html', server_url=SERVER_URL)

@app.route('/admin_logout')
def admin_logout():
    """Handle admin logout."""
    session.pop('admin_id', None)
    logging.info("Admin logged out")
    return redirect(url_for('admin_login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle operator login."""
    if request.method == 'POST':
        operator_id = request.form.get('operator_id', type=int)
        password = request.form.get('password')
        if not operator_id or not password:
            return render_template('login.html', error="Operator ID and password are required",
                                   server_url=SERVER_URL), 400
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT id, hashed_password FROM operators WHERE id = ?", (operator_id,))
            operator = c.fetchone()
            if operator and check_password_hash(operator[1], password):
                session['operator_id'] = operator[0]
                logging.info(f"Operator {operator_id} logged in")
                return redirect(url_for('operator'))
            logging.warning(f"Failed login attempt for operator {operator_id}")
            return render_template('login.html', error="Invalid credentials",
                                   server_url=SERVER_URL), 401
    return render_template('login.html', server_url=SERVER_URL)

@app.route('/logout')
@login_required
def logout():
    """Handle operator logout."""
    operator_id = session.pop('operator_id', None)
    logging.info(f"Operator {operator_id} logged out")
    return redirect(url_for('login'))

@app.route('/operator')
@login_required
def operator():
    """Render the operator dashboard."""
    operator_id = session['operator_id']
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, operator_number FROM operators WHERE status = 'active' ORDER BY name")
        operators = c.fetchall()
        c.execute("SELECT number, status, created_at FROM tickets WHERE operator_id = ? "
                  "AND status IN ('waiting', 'called') ORDER BY created_at",
                  (operator_id,))
        tickets = c.fetchall()
        c.execute("""
            SELECT c.ticket_number, c.sender_type, c.content, c.timestamp
            FROM chats c
            WHERE c.ticket_number IN (SELECT number FROM tickets WHERE operator_id = ?)
            ORDER BY c.timestamp DESC LIMIT 50
        """, (operator_id,))
        messages = c.fetchall()
        return render_template('operator.html', operator_id=operator_id, operators=operators,
                               tickets=tickets, messages=messages, server_url=SERVER_URL)

@app.route('/tablet/<int:operator_id>/data')
@login_required
def tablet_data(operator_id):
    """Fetch ticket data for the operator's tablet view."""
    if session['operator_id'] != operator_id:
        abort(403)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT number, status, created_at FROM tickets WHERE operator_id = ? "
                  "AND status IN ('waiting', 'called') ORDER BY created_at",
                  (operator_id,))
        tickets = [{"number": row[0], "status": row[1], "created_at": row[2]} for row in c.fetchall()]
        return jsonify(tickets)

@app.route('/call_ticket', methods=['POST'])
@login_required
def call_ticket():
    """Call the next waiting ticket for the operator."""
    operator_id = session['operator_id']
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT number FROM tickets WHERE operator_id = ? AND status = 'called'",
                  (operator_id,))
        if c.fetchone():
            return jsonify({"error": "You already have a called ticket"}), 400
        c.execute("""
            SELECT t.id, t.number
            FROM tickets t
            WHERE t.status = 'waiting' AND t.service_id IN (
                SELECT service_id FROM operator_services WHERE operator_id = ?
            )
            ORDER BY t.created_at LIMIT 1
        """, (operator_id,))
        ticket = c.fetchone()
        if ticket:
            ticket_id, ticket_number = ticket
            c.execute("UPDATE tickets SET status = 'called', operator_id = ? WHERE id = ?",
                      (operator_id, ticket_id))
            conn.commit()
            socketio.emit('update_queue', {'ticket': ticket_number, 'operator_id': operator_id})
            logging.info(f"Operator {operator_id} called ticket {ticket_number}")
            return jsonify({"ticket": ticket_number})
        return jsonify({"ticket": None})

@app.route('/finish_ticket', methods=['POST'])
@login_required
def finish_ticket():
    """Mark a ticket as finished."""
    data = request.get_json() or {}
    ticket_number = data.get('ticket')
    operator_id = session['operator_id']
    if not ticket_number:
        return jsonify({"error": "Ticket number is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE tickets SET status = 'finished', finished_at = ? "
                  "WHERE number = ? AND operator_id = ?",
                  (datetime.now().isoformat(), ticket_number, operator_id))
        if c.rowcount == 0:
            return jsonify({"error": "Ticket not found or not assigned to you"}), 404
        conn.commit()
        socketio.emit('remove_ticket', {'ticket': ticket_number})
        logging.info(f"Operator {operator_id} finished ticket {ticket_number}")
        return jsonify({"status": "ok"})

@app.route('/redirect_ticket', methods=['POST'])
@login_required
def redirect_ticket():
    """Redirect a ticket to another operator."""
    data = request.get_json() or {}
    ticket_number = data.get('ticket')
    new_operator_id = data.get('new_operator_id', type=int)
    operator_id = session['operator_id']
    if not ticket_number or not new_operator_id:
        return jsonify({"error": "Ticket number and new operator ID are required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE tickets SET operator_id = ?, status = 'waiting' "
                  "WHERE number = ? AND operator_id = ?",
                  (new_operator_id, ticket_number, operator_id))
        if c.rowcount == 0:
            return jsonify({"error": "Ticket not found or not assigned to you"}), 404
        conn.commit()
        socketio.emit('remove_ticket', {'ticket': ticket_number})
        socketio.emit('update_queue', {'ticket': ticket_number, 'operator_id': new_operator_id})
        logging.info(f"Operator {operator_id} redirected ticket {ticket_number} to {new_operator_id}")
        return jsonify({"status": "ok"})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    """Send a chat message for a ticket."""
    data = request.get_json() or {}
    operator_id = session['operator_id']
    ticket_number = data.get('ticket_number')
    content = data.get('content')
    if not ticket_number or not content:
        return jsonify({"error": "Ticket number and message content are required"}), 400
    timestamp = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO chats (ticket_number, sender_type, sender_id, content, timestamp) "
                  "VALUES (?, 'operator', ?, ?, ?)",
                  (ticket_number, operator_id, content, timestamp))
        conn.commit()
        socketio.emit('message', {
            'room': ticket_number,
            'sender': f"Operator {operator_id}",
            'content': content,
            'timestamp': timestamp
        })
        logging.info(f"Operator {operator_id} sent message to ticket {ticket_number}: {content}")
        return jsonify({"status": "ok"})

@app.route('/api/admin/upload_media', methods=['POST'])
@admin_required
def upload_media():
    """Upload media files for the display."""
    if 'file' not in request.files:
        logging.error("No file uploaded")
        return jsonify({"status": "error", "message": "No file provided"}), 400
    file = request.files['file']
    if file.filename == '':
        logging.error("Empty filename")
        return jsonify({"status": "error", "message": "No file selected"}), 400
    if not allowed_file(file.filename):
        logging.error(f"Invalid file type: {file.filename}")
        return jsonify({"status": "error", "message": "Invalid file type"}), 400
    original_filename = file.filename
    filename = secure_filename(f"{uuid.uuid4()}_{original_filename}")
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    if file_size > 100 * 1024 * 1024:  # 100MB limit
        os.remove(file_path)
        logging.error(f"File {filename} exceeds 100MB limit")
        return jsonify({"status": "error", "message": "File size exceeds 100MB"}), 400
    media_type = 'image' if filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png'} else 'video'
    title = request.form.get('title', '')
    description = request.form.get('description', '')
    display_order = request.form.get('display_order', 0, type=int)
    is_active = 1 if request.form.get('is_active') == 'on' else 0
    duration = request.form.get('duration', 10, type=int) if media_type == 'image' else None
    created_at = datetime.now().isoformat()
    admin_id = session['admin_id']
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO media (type, filename, original_filename, title, description, display_order,
                              is_active, duration, created_at, uploaded_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (media_type, filename, original_filename, title, description, display_order,
              is_active, duration, created_at, admin_id))
        conn.commit()
        logging.info(f"Uploaded media: {filename}, type: {media_type}, size: {file_size} bytes")
        socketio.emit('media_playlist_updated')
        return jsonify({"status": "ok", "filename": filename})

@app.route('/admin/media', methods=['GET'])
@admin_required
def get_media():
    """Fetch all media items."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, type, filename, original_filename, title, description,
                   display_order, is_active, duration
            FROM media
            ORDER BY display_order, created_at
        """)
        media = [{
            "id": row[0],
            "type": row[1],
            "filename": row[2],
            "original_filename": row[3],
            "title": row[4],
            "description": row[5],
            "display_order": row[6],
            "is_active": row[7],
            "duration": row[8]
        } for row in c.fetchall()]
        logging.info(f"Fetched {len(media)} media items")
        return jsonify(media)

@app.route('/admin/delete_media', methods=['POST'])
@admin_required
def delete_media():
    """Delete a media item."""
    data = request.get_json() or {}
    media_id = data.get('id', type=int)
    if not media_id:
        return jsonify({"status": "error", "message": "Media ID is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT filename FROM media WHERE id = ?", (media_id,))
        media = c.fetchone()
        if not media:
            logging.error(f"Media ID {media_id} not found")
            return jsonify({"status": "error", "message": "Media not found"}), 404
        filename = media[0]
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            logging.info(f"Removed file: {file_path}")
        c.execute("DELETE FROM media WHERE id = ?", (media_id,))
        conn.commit()
        logging.info(f"Deleted media: ID {media_id}, filename: {filename}")
        socketio.emit('media_playlist_updated')
        return jsonify({"status": "ok"})

@app.route('/api/admin/media/update', methods=['POST'])
@admin_required
def update_media():
    """Update a media item's details."""
    data = request.get_json() or {}
    media_id = data.get('id', type=int)
    title = data.get('title')
    description = data.get('description')
    display_order = data.get('display_order', type=int)
    is_active = data.get('is_active', type=int)
    duration = data.get('duration', type=int)
    if not media_id:
        return jsonify({"status": "error", "message": "Media ID is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT filename FROM media WHERE id = ?", (media_id,))
        if not c.fetchone():
            logging.error(f"Media ID {media_id} not found")
            return jsonify({"status": "error", "message": "Media not found"}), 404
        update_fields = []
        update_params = []
        if title is not None:
            update_fields.append("title = ?")
            update_params.append(title)
        if description is not None:
            update_fields.append("description = ?")
            update_params.append(description)
        if display_order is not None:
            update_fields.append("display_order = ?")
            update_params.append(display_order)
        if is_active is not None:
            update_fields.append("is_active = ?")
            update_params.append(is_active)
        if duration is not None:
            update_fields.append("duration = ?")
            update_params.append(duration)
        if update_fields:
            update_params.append(media_id)
            c.execute(f"UPDATE media SET {', '.join(update_fields)} WHERE id = ?", update_params)
            conn.commit()
            logging.info(f"Updated media ID {media_id}")
            socketio.emit('media_playlist_updated')
        return jsonify({"status": "ok"})

@app.route('/api/admin/media/toggle_active', methods=['POST'])
@admin_required
def toggle_media_active():
    """Toggle the active status of a media item."""
    data = request.get_json() or {}
    media_id = data.get('id', type=int)
    if not media_id:
        return jsonify({"status": "error", "message": "Media ID is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT is_active FROM media WHERE id = ?", (media_id,))
        media = c.fetchone()
        if not media:
            logging.error(f"Media ID {media_id} not found")
            return jsonify({"status": "error", "message": "Media not found"}), 404
        new_status = 0 if media[0] == 1 else 1
        c.execute("UPDATE media SET is_active = ? WHERE id = ?", (new_status, media_id))
        conn.commit()
        logging.info(f"Toggled media ID {media_id} to active={new_status}")
        socketio.emit('media_playlist_updated')
        return jsonify({"status": "ok", "is_active": new_status})

@app.route('/api/admin/media/reorder', methods=['POST'])
@admin_required
def reorder_media():
    """Reorder media items based on provided IDs."""
    data = request.get_json() or {}
    media_ids = data.get('ids', [])
    if not media_ids or not isinstance(media_ids, list):
        return jsonify({"status": "error", "message": "Invalid or missing IDs"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        for index, media_id in enumerate(media_ids):
            c.execute("UPDATE media SET display_order = ? WHERE id = ?", (index, media_id))
        conn.commit()
        logging.info(f"Reordered media: {media_ids}")
        socketio.emit('media_playlist_updated')
        return jsonify({"status": "ok"})

@app.route('/api/display/playlist', methods=['GET'])
def get_playlist():
    """Fetch the active media playlist for the display."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT filename, type, duration FROM media WHERE is_active = 1 "
                  "ORDER BY display_order, created_at")
        playlist = [{"filename": row[0], "type": row[1], "duration": row[2]} for row in c.fetchall()]
        logging.info(f"Fetched playlist with {len(playlist)} items")
        return jsonify(playlist)

@socketio.on('join')
def handle_join(data):
    """Handle a client joining a socket room."""
    room = data.get('room')
    if room:
        join_room(room)
        logging.info(f"User joined room {room}")

@socketio.on('message')
def handle_message(data):
    """Handle chat messages via SocketIO."""
    room = data.get('room')
    content = data.get('content')
    sender_id = data.get('sender_id')
    ticket_number = data.get('ticket_number')
    sender_type = data.get('sender_type', 'operator')
    sender = data.get('sender', f"Operator {sender_id}")
    if not room or not content or not ticket_number:
        logging.error("Invalid message data")
        return
    timestamp = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO chats (ticket_number, sender_type, sender_id, content, timestamp) "
                  "VALUES (?, ?, ?, ?, ?)",
                  (ticket_number, sender_type, sender_id, content, timestamp))
        conn.commit()
        emit('message', {
            'sender': sender,
            'content': content,
            'timestamp': timestamp
        }, room=room)
        logging.info(f"Message in room {room} from {sender}: {content}")

@app.route('/admin')
@admin_required
def admin():
    """Render the admin dashboard."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, parent_id, color FROM categories ORDER BY name")
        categories = c.fetchall()
        c.execute("SELECT s.id, s.name, c.name, s.color FROM services s "
                  "JOIN categories c ON s.category_id = c.id ORDER BY s.name")
        services = c.fetchall()
        c.execute("SELECT id, name, status, operator_number FROM operators ORDER BY name")
        operators = c.fetchall()
        c.execute("SELECT operator_id, service_id FROM operator_services")
        operator_services = c.fetchall()
        c.execute("SELECT number, service_id FROM tickets WHERE status = 'waiting' ORDER BY created_at")
        waiting = c.fetchall()
        c.execute("SELECT number, service_id, operator_id, created_at, finished_at "
                  "FROM tickets WHERE status = 'finished' ORDER BY finished_at DESC LIMIT 100")
        stats = c.fetchall()
        c.execute("SELECT AVG(strftime('%s', finished_at) - strftime('%s', created_at)) / 60.0 "
                  "FROM tickets WHERE finished_at IS NOT NULL")
        avg_time = round(c.fetchone()[0] or 0, 1)
        c.execute("SELECT id, type, filename, original_filename, title, description, "
                  "display_order, is_active, duration FROM media ORDER BY display_order, created_at")
        media = c.fetchall()
        return render_template('admin.html', categories=categories, services=services,
                               operators=operators, operator_services=operator_services,
                               waiting=waiting, stats=stats, avg_time=avg_time,
                               media=media, server_url=SERVER_URL)

@app.route('/admin/statistics')
@admin_required
def admin_statistics():
    """Render the admin statistics page."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM categories ORDER BY name")
        categories = c.fetchall()
        c.execute("SELECT id, name FROM services ORDER BY name")
        services = c.fetchall()
        c.execute("SELECT id, name FROM operators ORDER BY name")
        operators = c.fetchall()
        return render_template('admin_statistics.html', categories=categories,
                               services=services, operators=operators, server_url=SERVER_URL)

@app.route('/add_category', methods=['POST'])
@admin_required
def add_category():
    """Add a new category."""
    name = request.form.get('name')
    parent_id = request.form.get('parent_id', type=int)
    color = request.form.get('color', '#FFFFFF')
    if not name:
        return jsonify({"status": "error", "message": "Category name is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        if parent_id:
            depth = get_category_depth(parent_id)
            if depth >= 10:
                logging.warning(f"Cannot add category '{name}' under {parent_id}: max depth reached")
                return jsonify({"status": "error", "message": "Maximum category depth reached"}), 400
        c.execute("INSERT INTO categories (name, parent_id, color) VALUES (?, ?, ?)",
                  (name, parent_id, color))
        conn.commit()
        logging.info(f"Added category: {name}, parent_id: {parent_id or 'None'}, color: {color}")
        return redirect(url_for('admin'))

@app.route('/edit_category', methods=['POST'])
@admin_required
def edit_category():
    """Edit an existing category."""
    data = request.get_json() or {}
    category_id = data.get('id', type=int)
    name = data.get('name')
    color = data.get('color', '#FFFFFF')
    if not category_id or not name:
        return jsonify({"status": "error", "message": "Category ID and name are required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE categories SET name = ?, color = ? WHERE id = ?",
                  (name, color, category_id))
        if c.rowcount == 0:
            return jsonify({"status": "error", "message": "Category not found"}), 404
        conn.commit()
        logging.info(f"Edited category {category_id}: {name}, color: {color}")
        return jsonify({"status": "ok"})

@app.route('/delete_category', methods=['POST'])
@admin_required
def delete_category():
    """Delete a category if it has no subcategories or services."""
    data = request.get_json() or {}
    category_id = data.get('id', type=int)
    if not category_id:
        return jsonify({"status": "error", "message": "Category ID is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ?", (category_id,))
        subcategories_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM services WHERE category_id = ?", (category_id,))
        services_count = c.fetchone()[0]
        if subcategories_count > 0 or services_count > 0:
            logging.warning(f"Cannot delete category {category_id}: has subcategories or services")
            return jsonify({"status": "error", "message": "Cannot delete category with subcategories or services"}), 400
        c.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        if c.rowcount == 0:
            return jsonify({"status": "error", "message": "Category not found"}), 404
        conn.commit()
        logging.info(f"Deleted category {category_id}")
        return jsonify({"status": "ok"})

@app.route('/add_service', methods=['POST'])
@admin_required
def add_service():
    """Add a new service."""
    name = request.form.get('name')
    category_id = request.form.get('category_id', type=int)
    color = request.form.get('color', '#FFFFFF')
    if not name or not category_id:
        return jsonify({"status": "error", "message": "Service name and category ID are required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO services (name, category_id, color) VALUES (?, ?, ?)",
                  (name, category_id, color))
        conn.commit()
        logging.info(f"Added service: {name}, category_id: {category_id}, color: {color}")
        return redirect(url_for('admin'))

@app.route('/edit_service', methods=['POST'])
@admin_required
def edit_service():
    """Edit an existing service."""
    data = request.get_json() or {}
    service_id = data.get('id', type=int)
    name = data.get('name')
    color = data.get('color', '#FFFFFF')
    if not service_id or not name:
        return jsonify({"status": "error", "message": "Service ID and name are required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE services SET name = ?, color = ? WHERE id = ?",
                  (name, color, service_id))
        if c.rowcount == 0:
            return jsonify({"status": "error", "message": "Service not found"}), 404
        conn.commit()
        logging.info(f"Edited service {service_id}: {name}, color: {color}")
        return jsonify({"status": "ok"})

@app.route('/delete_service', methods=['POST'])
@admin_required
def delete_service():
    """Delete a service if not assigned to operators."""
    data = request.get_json() or {}
    service_id = data.get('id', type=int)
    if not service_id:
        return jsonify({"status": "error", "message": "Service ID is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM operator_services WHERE service_id = ?", (service_id,))
        if c.fetchone()[0] > 0:
            return jsonify({"status": "error", "message": "Cannot delete service assigned to operators"}), 400
        c.execute("DELETE FROM services WHERE id = ?", (service_id,))
        if c.rowcount == 0:
            return jsonify({"status": "error", "message": "Service not found"}), 404
        conn.commit()
        logging.info(f"Deleted service {service_id}")
        return jsonify({"status": "ok"})

@app.route('/add_operator', methods=['POST'])
@admin_required
def add_operator():
    """Add a new operator."""
    name = request.form.get('name')
    password = request.form.get('password')
    operator_number = request.form.get('operator_number', type=int)
    status = request.form.get('status', 'active')
    if not name or not password:
        return jsonify({"status": "error", "message": "Name and password are required"}), 400
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            c.execute("INSERT INTO operators (name, hashed_password, status, operator_number) "
                      "VALUES (?, ?, ?, ?)",
                      (name, hashed_password, status, operator_number))
            conn.commit()
            logging.info(f"Added operator: {name}, number: {operator_number or 'None'}")
            return redirect(url_for('admin'))
        except sqlite3.IntegrityError:
            logging.error(f"Failed to add operator {name}: duplicate operator number")
            return jsonify({"status": "error", "message": "Operator number already exists"}), 400

@app.route('/edit_operator', methods=['POST'])
@admin_required
def edit_operator():
    """Edit an existing operator."""
    data = request.get_json() or {}
    operator_id = data.get('id', type=int)
    name = data.get('name')
    password = data.get('password')
    status = data.get('status')
    operator_number = data.get('operator_number', type=int)
    if not operator_id or not name or not status:
        return jsonify({"status": "error", "message": "Operator ID, name, and status are required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            if password:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                c.execute("UPDATE operators SET name = ?, hashed_password = ?, status = ?, operator_number = ? "
                          "WHERE id = ?",
                          (name, hashed_password, status, operator_number, operator_id))
            else:
                c.execute("UPDATE operators SET name = ?, status = ?, operator_number = ? WHERE id = ?",
                          (name, status, operator_number, operator_id))
            if c.rowcount == 0:
                return jsonify({"status": "error", "message": "Operator not found"}), 404
            conn.commit()
            logging.info(f"Edited operator {operator_id}: {name}, status: {status}")
            return jsonify({"status": "ok"})
        except sqlite3.IntegrityError:
            logging.error(f"Failed to edit operator {operator_id}: duplicate operator number")
            return jsonify({"status": "error", "message": "Operator number already exists"}), 400

@app.route('/delete_operator', methods=['POST'])
@admin_required
def delete_operator():
    """Delete an operator and their service assignments."""
    data = request.get_json() or {}
    operator_id = data.get('id', type=int)
    if not operator_id:
        return jsonify({"status": "error", "message": "Operator ID is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM operator_services WHERE operator_id = ?", (operator_id,))
        c.execute("DELETE FROM operators WHERE id = ?", (operator_id,))
        if c.rowcount == 0:
            return jsonify({"status": "error", "message": "Operator not found"}), 404
        conn.commit()
        logging.info(f"Deleted operator {operator_id}")
        return jsonify({"status": "ok"})

@app.route('/assign_service', methods=['POST'])
@admin_required
def assign_service():
    """Assign a service to an operator."""
    data = request.get_json() or {}
    operator_id = data.get('operator_id', type=int)
    service_id = data.get('service_id', type=int)
    if not operator_id or not service_id:
        return jsonify({"status": "error", "message": "Operator ID and service ID are required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM operator_services WHERE operator_id = ? AND service_id = ?",
                  (operator_id, service_id))
        if c.fetchone()[0] > 0:
            logging.warning(f"Service {service_id} already assigned to operator {operator_id}")
            return jsonify({"status": "error", "message": "Service already assigned"}), 400
        c.execute("INSERT INTO operator_services (operator_id, service_id) VALUES (?, ?)",
                  (operator_id, service_id))
        conn.commit()
        logging.info(f"Assigned service {service_id} to operator {operator_id}")
        return jsonify({"status": "ok"})

@app.route('/unassign_service', methods=['POST'])
@admin_required
def unassign_service():
    """Unassign a service from an operator."""
    data = request.get_json() or {}
    operator_id = data.get('operator_id', type=int)
    service_id = data.get('service_id', type=int)
    if not operator_id or not service_id:
        return jsonify({"status": "error", "message": "Operator ID and service ID are required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM operator_services WHERE operator_id = ? AND service_id = ?",
                  (operator_id, service_id))
        if c.rowcount == 0:
            return jsonify({"status": "error", "message": "Assignment not found"}), 404
        conn.commit()
        logging.info(f"Unassigned service {service_id} from operator {operator_id}")
        return jsonify({"status": "ok"})

@app.route('/display')
def display():
    """Render the display panel."""
    return render_template('display.html', server_url=SERVER_URL)

@app.route('/tablet/<int:operator_id>')
@login_required
def tablet(operator_id):
    """Render the tablet interface for an operator."""
    if session['operator_id'] != operator_id:
        abort(403)
    return render_template('tablet.html', operator_id=operator_id, server_url=SERVER_URL)

@app.route('/get_queue')
def get_queue():
    """Fetch the current queue of called tickets."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT t.number, o.name, o.operator_number FROM tickets t "
                  "LEFT JOIN operators o ON t.operator_id = o.id "
                  "WHERE t.status = 'called' ORDER BY t.created_at")
        tickets = [{
            "ticket": row[0],
            "operator_name": row[1],
            "operator_number": row[2]
        } for row in c.fetchall()]
        logging.info(f"Fetched {len(tickets)} called tickets for queue")
        return jsonify(tickets)

@app.route('/operator/<int:operator_id>/tickets')
@login_required
def operator_tickets(operator_id):
    """Fetch tickets assigned to an operator."""
    if session['operator_id'] != operator_id:
        abort(403)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT number, status, created_at FROM tickets WHERE operator_id = ? "
                  "AND status IN ('waiting', 'called') ORDER BY created_at",
                  (operator_id,))
        tickets = [{
            "number": row[0],
            "status": row[1],
            "created_at": row[2]
        } for row in c.fetchall()]
        logging.info(f"Fetched {len(tickets)} tickets for operator {operator_id}")
        return jsonify(tickets)

if __name__ == '__main__':
    init_db()
    socketio.run(app, host=os.getenv('HOST', '0.0.0.0'), port=int(os.getenv('PORT', 5000)),
                 debug=os.getenv('DEBUG', 'True') == 'True')