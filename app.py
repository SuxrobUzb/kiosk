from flask import Flask, jsonify, request, render_template, redirect, url_for, session, abort
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_session import Session
import sqlite3
from datetime import datetime
import secrets
import logging
import getpass
from dotenv import load_dotenv
import os

# Загружаем переменные из .env
load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# Получаем SERVER_URL из .env
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000")

# Настройка логирования
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

# Декоратор для проверки авторизации оператора
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'operator_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Декоратор для проверки авторизации администратора
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS categories (
                 id INTEGER PRIMARY KEY, 
                 name TEXT, 
                 parent_id INTEGER, 
                 FOREIGN KEY(parent_id) REFERENCES categories(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS services (
                 id INTEGER PRIMARY KEY, 
                 name TEXT, 
                 category_id INTEGER, 
                 FOREIGN KEY(category_id) REFERENCES categories(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS operators (
                 id INTEGER PRIMARY KEY, 
                 name TEXT, 
                 password TEXT, 
                 status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS operator_services (
                 operator_id INTEGER, 
                 service_id INTEGER, 
                 FOREIGN KEY(operator_id) REFERENCES operators(id), 
                 FOREIGN KEY(service_id) REFERENCES services(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS tickets (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 number TEXT, 
                 service_id INTEGER, 
                 status TEXT, 
                 operator_id INTEGER, 
                 created_at TEXT, 
                 finished_at TEXT, 
                 kiosk_id INTEGER,
                 FOREIGN KEY(service_id) REFERENCES services(id), 
                 FOREIGN KEY(operator_id) REFERENCES operators(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 operator_id INTEGER, 
                 content TEXT, 
                 timestamp TEXT, 
                 FOREIGN KEY(operator_id) REFERENCES operators(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL)''')
    conn.commit()

    # Проверяем наличие администратора
    c.execute("SELECT COUNT(*) FROM admin_users")
    admin_count = c.fetchone()[0]
    if admin_count == 0:
        print("Администратор не найден. Создание нового администратора.")
        username = input("Введите имя пользователя для администратора: ")
        password = getpass.getpass("Введите пароль для администратора: ")
        c.execute("INSERT INTO admin_users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        logging.info(f"Создан новый администратор: {username}")
    conn.close()

# Проверка уровня вложенности категорий
def get_category_depth(category_id):
    conn = sqlite3.connect('regoffice.db')
    depth = 0
    current_id = category_id
    c = conn.cursor()
    while current_id:
        c.execute("SELECT parent_id FROM categories WHERE id = ?", (current_id,))
        result = c.fetchone()
        if not result or result[0] is None:
            break
        current_id = result[0]
        depth += 1
        if depth >= 10:
            return 10
    conn.close()
    return depth

@app.route('/')
def index():
    return render_template('index.html', server_url=SERVER_URL)

@app.route('/categories', methods=['GET'])
def get_categories():
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("SELECT id, name, parent_id FROM categories WHERE parent_id IS NULL")
    categories = [{"id": row[0], "name": row[1], "isCategory": True, "isSubcategory": False} for row in c.fetchall()]
    conn.close()
    return jsonify(categories)

@app.route('/services/<int:category_id>', methods=['GET'])
def get_services(category_id):
    page = int(request.args.get('page', 1))
    per_page = 10
    offset = (page - 1) * per_page

    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    
    # Получаем подкатегории
    c.execute("SELECT id, name, parent_id FROM categories WHERE parent_id = ? LIMIT ? OFFSET ?", 
              (category_id, per_page, offset))
    subcategories = [{"id": row[0], "name": row[1], "isCategory": True, "isSubcategory": row[2] is not None} for row in c.fetchall()]
    c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ?", (category_id,))
    total_subcategories = c.fetchone()[0]
    
    # Получаем услуги
    c.execute("SELECT id, name, category_id FROM services WHERE category_id = ? LIMIT ? OFFSET ?", 
              (category_id, per_page, offset))
    services = [{"id": row[0], "name": row[1], "isCategory": False, "isSubcategory": False, "category_id": row[2]} for row in c.fetchall()]
    c.execute("SELECT COUNT(*) FROM services WHERE category_id = ?", (category_id,))
    total_services = c.fetchone()[0]
    
    # Объединяем подкатегории и услуги
    items = subcategories + services
    total = total_subcategories + total_services
    
    conn.close()
    return jsonify({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page
    })

@app.route('/get_ticket', methods=['POST'])
def get_ticket():
    data = request.get_json()
    service_id = data.get('service_id')
    lang = data.get('lang', 'uz_lat')
    kiosk_id = data.get('kiosk_id', 1)
    
    logging.info(f"Received get_ticket request: service_id={service_id}, lang={lang}, kiosk_id={kiosk_id}")
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM tickets WHERE service_id = ? AND DATE(created_at) = DATE('now')", (service_id,))
    count = c.fetchone()[0] + 1
    ticket_number = f"{service_id:02d}-{count:03d}"
    
    c.execute("SELECT AVG(strftime('%s', finished_at) - strftime('%s', created_at)) / 60 FROM tickets WHERE service_id = ? AND finished_at IS NOT NULL", (service_id,))
    avg_time = c.fetchone()[0] or 5
    wait_time = round(avg_time * count / 60)
    
    # Автоматическое назначение оператора
    c.execute("SELECT operator_id FROM operator_services WHERE service_id = ? LIMIT 1", (service_id,))
    operator = c.fetchone()
    operator_id = operator[0] if operator else None
    
    c.execute("INSERT INTO tickets (number, service_id, status, operator_id, created_at, kiosk_id) VALUES (?, ?, 'waiting', ?, ?, ?)", 
              (ticket_number, service_id, operator_id, datetime.now().isoformat(), kiosk_id))
    conn.commit()
    
    # Уведомление через WebSocket
    socketio.emit('new_ticket', {'ticket': ticket_number, 'service_id': service_id, 'operator_id': operator_id})
    logging.info(f"New ticket created: {ticket_number} for service {service_id}, assigned to operator {operator_id or 'None'}")
    
    conn.close()
    return jsonify({"ticket": ticket_number, "wait_time": wait_time})

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('regoffice.db')
        c = conn.cursor()
        c.execute("SELECT id FROM admin_users WHERE username = ? AND password = ?", (username, password))
        admin = c.fetchone()
        conn.close()
        
        if admin:
            session['admin_id'] = admin[0]
            logging.info(f"Admin {username} logged in")
            return redirect(url_for('admin'))
        else:
            logging.warning(f"Failed admin login attempt for {username}")
            return render_template('admin_login.html', error="Noto‘g‘ri login yoki parol", server_url=SERVER_URL)
    return render_template('admin_login.html', server_url=SERVER_URL)

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_id', None)
    logging.info("Admin logged out")
    return redirect(url_for('admin_login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        operator_id = request.form.get('operator_id')
        password = request.form.get('password')
        
        conn = sqlite3.connect('regoffice.db')
        c = conn.cursor()
        c.execute("SELECT id, password FROM operators WHERE id = ? AND password = ?", (operator_id, password))
        operator = c.fetchone()
        conn.close()
        
        if operator:
            session['operator_id'] = operator[0]
            logging.info(f"Operator {operator_id} logged in")
            return redirect(url_for('operator'))
        else:
            logging.warning(f"Failed login attempt for operator {operator_id}")
            return render_template('login.html', error="Noto‘g‘ri ID yoki parol", server_url=SERVER_URL)
    return render_template('login.html', server_url=SERVER_URL)

@app.route('/logout')
@login_required
def logout():
    operator_id = session.pop('operator_id', None)
    logging.info(f"Operator {operator_id} logged out")
    return redirect(url_for('login'))

@app.route('/operator')
@login_required
def operator():
    operator_id = session['operator_id']
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    
    c.execute("SELECT id, name FROM operators")
    operators = c.fetchall()
    
    c.execute("SELECT number, status FROM tickets WHERE operator_id = ? AND status IN ('waiting', 'called')", (operator_id,))
    tickets = c.fetchall()
    
    c.execute("SELECT operator_id, content, timestamp FROM messages ORDER BY timestamp DESC LIMIT 50")
    messages = c.fetchall()
    
    conn.close()
    return render_template('operator.html', operator_id=operator_id, operators=operators, tickets=tickets, messages=messages, server_url=SERVER_URL)

@app.route('/tablet/<int:operator_id>/data')
@login_required
def tablet_data(operator_id):
    if session['operator_id'] != operator_id:
        abort(403)
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("SELECT number, status FROM tickets WHERE operator_id = ? AND status IN ('waiting', 'called')", (operator_id,))
    tickets = [{"number": row[0], "status": row[1]} for row in c.fetchall()]
    conn.close()
    return jsonify(tickets)

@app.route('/call_ticket', methods=['POST'])
@login_required
def call_ticket():
    operator_id = session['operator_id']
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    
    c.execute("SELECT number FROM tickets WHERE operator_id = ? AND status = 'called'", (operator_id,))
    current_ticket = c.fetchone()
    if current_ticket:
        conn.close()
        return jsonify({"error": "Sizda allaqachon chaqirilgan taloon bor!"}), 400
    
    c.execute("SELECT id, number FROM tickets WHERE status = 'waiting' AND service_id IN (SELECT service_id FROM operator_services WHERE operator_id = ?) ORDER BY created_at LIMIT 1", (operator_id,))
    ticket = c.fetchone()
    
    if ticket:
        ticket_id, ticket_number = ticket
        c.execute("UPDATE tickets SET status = 'called', operator_id = ? WHERE id = ?", (operator_id, ticket_id))
        conn.commit()
        socketio.emit('update_queue', {'ticket': ticket_number, 'operator_id': operator_id})
        logging.info(f"Operator {operator_id} called ticket {ticket_number}")
    conn.close()
    return jsonify({"ticket": ticket_number if ticket else None})

@app.route('/finish_ticket', methods=['POST'])
@login_required
def finish_ticket():
    data = request.get_json()
    ticket = data.get('ticket')
    operator_id = session['operator_id']
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("UPDATE tickets SET status = 'finished', finished_at = ? WHERE number = ? AND operator_id = ?", 
              (datetime.now().isoformat(), ticket, operator_id))
    if c.rowcount == 0:
        conn.close()
        return jsonify({"error": "Talon topilmadi yoki sizniki emas"}), 400
    
    conn.commit()
    socketio.emit('remove_ticket', {'ticket': ticket})
    logging.info(f"Operator {operator_id} finished ticket {ticket}")
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/redirect_ticket', methods=['POST'])
@login_required
def redirect_ticket():
    data = request.get_json()
    ticket = data.get('ticket')
    new_operator_id = data.get('new_operator_id')
    operator_id = session['operator_id']
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("UPDATE tickets SET operator_id = ?, status = 'waiting' WHERE number = ? AND operator_id = ?", 
              (new_operator_id, ticket, operator_id))
    if c.rowcount == 0:
        conn.close()
        return jsonify({"error": "Talon topilmadi yoki sizniki emas"}), 400
    
    conn.commit()
    socketio.emit('remove_ticket', {'ticket': ticket})
    socketio.emit('update_queue', {'ticket': ticket, 'operator_id': new_operator_id})
    logging.info(f"Operator {operator_id} redirected ticket {ticket} to {new_operator_id}")
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    data = request.get_json()
    operator_id = session['operator_id']
    content = data.get('content')
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO messages (operator_id, content, timestamp) VALUES (?, ?, ?)", 
              (operator_id, content, timestamp))
    conn.commit()
    socketio.emit('new_message', {'operator_id': operator_id, 'content': content, 'timestamp': timestamp})
    logging.info(f"Operator {operator_id} sent message: {content}")
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/admin')
@admin_required
def admin():
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    
    c.execute("SELECT id, name, parent_id FROM categories")
    categories = c.fetchall()
    
    c.execute("SELECT s.id, s.name, c.name FROM services s JOIN categories c ON s.category_id = c.id")
    services = c.fetchall()
    
    c.execute("SELECT id, name, status FROM operators")
    operators = c.fetchall()
    
    c.execute("SELECT operator_id, service_id FROM operator_services")
    operator_services = c.fetchall()
    
    c.execute("SELECT number, service_id FROM tickets WHERE status = 'waiting'")
    waiting = c.fetchall()
    
    c.execute("SELECT number, service_id, operator_id, created_at, finished_at FROM tickets WHERE status = 'finished'")
    stats = c.fetchall()
    
    c.execute("SELECT AVG(strftime('%s', finished_at) - strftime('%s', created_at)) / 60 FROM tickets WHERE finished_at IS NOT NULL")
    avg_time = round(c.fetchone()[0] or 0, 2)
    
    conn.close()
    return render_template('admin.html', categories=categories, services=services, operators=operators, 
                           operator_services=operator_services, waiting=waiting, stats=stats, avg_time=avg_time, server_url=SERVER_URL)

@app.route('/add_category', methods=['POST'])
@admin_required
def add_category():
    name = request.form.get('name')
    parent_id = request.form.get('parent_id')
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    
    if parent_id:
        depth = get_category_depth(int(parent_id))
        if depth >= 9:
            conn.close()
            logging.warning(f"Cannot add category '{name}' under {parent_id}: maximum depth (10) reached")
            return jsonify({"status": "error", "message": "Maksimal 10 darajali kategoriya chegarasiga yetdi"}), 400
    
    c.execute("INSERT INTO categories (name, parent_id) VALUES (?, ?)", (name, parent_id or None))
    conn.commit()
    conn.close()
    logging.info(f"New category added: {name} (parent_id: {parent_id or 'None'})")
    return redirect(url_for('admin'))

@app.route('/edit_category', methods=['POST'])
@admin_required
def edit_category():
    data = request.get_json()
    category_id = data['id']
    new_name = data['name']
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("UPDATE categories SET name = ? WHERE id = ?", (new_name, category_id))
    conn.commit()
    conn.close()
    logging.info(f"Category {category_id} edited: {new_name}")
    return jsonify({"status": "ok"})

@app.route('/delete_category', methods=['POST'])
@admin_required
def delete_category():
    data = request.get_json()
    category_id = data['id']
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    
    # Проверяем, есть ли подкатегории
    c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ?", (category_id,))
    subcategories_count = c.fetchone()[0]
    
    # Проверяем, есть ли услуги
    c.execute("SELECT COUNT(*) FROM services WHERE category_id = ?", (category_id,))
    services_count = c.fetchone()[0]
    
    if subcategories_count > 0 or services_count > 0:
        conn.close()
        logging.warning(f"Cannot delete category {category_id}: it has {subcategories_count} subcategories and {services_count} services")
        return jsonify({"status": "error", "message": "Kategoriyani o‘chirish mumkin emas, chunki unda xizmatlar yoki podkategoriyalar bor"}), 400
    
    c.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    conn.commit()
    conn.close()
    logging.info(f"Category {category_id} deleted")
    return jsonify({"status": "ok"})

@app.route('/add_service', methods=['POST'])
@admin_required
def add_service():
    name = request.form.get('name')
    category_id = request.form.get('category_id')
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("INSERT INTO services (name, category_id) VALUES (?, ?)", (name, category_id))
    conn.commit()
    conn.close()
    logging.info(f"New service added: {name} in category {category_id}")
    return redirect(url_for('admin'))

@app.route('/edit_service', methods=['POST'])
@admin_required
def edit_service():
    data = request.get_json()
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("UPDATE services SET name = ? WHERE id = ?", (data['name'], data['id']))
    conn.commit()
    conn.close()
    logging.info(f"Service {data['id']} edited: {data['name']}")
    return jsonify({"status": "ok"})

@app.route('/delete_service', methods=['POST'])
@admin_required
def delete_service():
    data = request.get_json()
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("DELETE FROM services WHERE id = ?", (data['id'],))
    conn.commit()
    conn.close()
    logging.info(f"Service {data['id']} deleted")
    return jsonify({"status": "ok"})

@app.route('/add_operator', methods=['POST'])
@admin_required
def add_operator():
    name = request.form.get('name')
    password = request.form.get('password')
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("INSERT INTO operators (name, password, status) VALUES (?, ?, 'active')", (name, password))
    conn.commit()
    conn.close()
    logging.info(f"New operator added: {name}")
    return redirect(url_for('admin'))

@app.route('/edit_operator', methods=['POST'])
@admin_required
def edit_operator():
    data = request.get_json()
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    if data.get('password'):
        c.execute("UPDATE operators SET name = ?, password = ?, status = ? WHERE id = ?", 
                  (data['name'], data['password'], data['status'], data['id']))
    else:
        c.execute("UPDATE operators SET name = ?, status = ? WHERE id = ?", 
                  (data['name'], data['status'], data['id']))
    conn.commit()
    conn.close()
    logging.info(f"Operator {data['id']} edited: {data['name']}")
    return jsonify({"status": "ok"})

@app.route('/delete_operator', methods=['POST'])
@admin_required
def delete_operator():
    data = request.get_json()
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("DELETE FROM operators WHERE id = ?", (data['id'],))
    conn.commit()
    conn.close()
    logging.info(f"Operator {data['id']} deleted")
    return jsonify({"status": "ok"})

@app.route('/assign_service', methods=['POST'])
@admin_required
def assign_service():
    data = request.get_json()
    operator_id = data['operator_id']
    service_id = data['service_id']
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("SELECT * FROM operator_services WHERE operator_id = ? AND service_id = ?", (operator_id, service_id))
    if c.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Bu xizmat allaqachon biriktirilgan"})
    
    c.execute("INSERT INTO operator_services (operator_id, service_id) VALUES (?, ?)", (operator_id, service_id))
    conn.commit()
    conn.close()
    logging.info(f"Service {service_id} assigned to operator {operator_id}")
    return jsonify({"status": "ok"})

@app.route('/unassign_service', methods=['POST'])
@admin_required
def unassign_service():
    data = request.get_json()
    operator_id = data['operator_id']
    service_id = data['service_id']
    
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("DELETE FROM operator_services WHERE operator_id = ? AND service_id = ?", (operator_id, service_id))
    conn.commit()
    conn.close()
    logging.info(f"Service {service_id} unassigned from operator {operator_id}")
    return jsonify({"status": "ok"})

@app.route('/display')
def display():
    return render_template('display.html', server_url=SERVER_URL)

@app.route('/tablet/<int:operator_id>')
@login_required
def tablet(operator_id):
    if session['operator_id'] != operator_id:
        abort(403)
    return render_template('tablet.html', operator_id=operator_id, server_url=SERVER_URL)

@app.route('/get_queue')
def get_queue():
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("SELECT t.number, o.name FROM tickets t LEFT JOIN operators o ON t.operator_id = o.id WHERE t.status = 'called'")
    tickets = [{"ticket": row[0], "operator_name": row[1]} for row in c.fetchall()]
    conn.close()
    return jsonify(tickets)

@app.route('/operator/<int:operator_id>/tickets')
@login_required
def operator_tickets(operator_id):
    if session['operator_id'] != operator_id:
        abort(403)
    conn = sqlite3.connect('regoffice.db')
    c = conn.cursor()
    c.execute("SELECT number, status FROM tickets WHERE operator_id = ? AND status IN ('waiting', 'called')", (operator_id,))
    tickets = [{"number": row[0], "status": row[1]} for row in c.fetchall()]
    conn.close()
    return jsonify(tickets)

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)