import os
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, abort, send_file
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_restx import Api, Resource, fields
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime, Text
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.sql import func
from datetime import datetime, timedelta
import secrets
import logging
from dotenv import load_dotenv
import qrcode
from PIL import Image
import uuid
import pandas as pd
from io import BytesIO
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from slugify import slugify
import pytz
from urllib.parse import urlparse
import json
import requests
from celery import Celery
import functools

# --- Configuration and Initialization ---

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), 'flask_session_data')
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
Session(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# CORS configuration
CORS(app, resources={r"/api/*": {"origins": os.getenv("TRUSTED_ORIGIN", "http://172.16.1.28:5000")}}, supports_credentials=True)

# Socket.IO initialization
socketio = SocketIO(app, cors_allowed_origins=os.getenv("TRUSTED_ORIGIN", "http://172.16.1.28:5000"), manage_session=False)

# Database configuration (PostgreSQL)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/regoffice")
engine = create_engine(DATABASE_URL, pool_size=20, max_overflow=0)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

# Media folder
MEDIA_FOLDER = 'static/uploads'
os.makedirs(MEDIA_FOLDER, exist_ok=True)

# Server URL
SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:5000")
PARSED_SERVER_URL = urlparse(SERVER_URL)
BASE_URL_FOR_QR = f"{PARSED_SERVER_URL.scheme}://{PARSED_SERVER_URL.netloc}"

# Timezone
UZBEKISTAN_TIMEZONE = pytz.timezone('Asia/Tashkent')

# Celery configuration
app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Swagger API
api = Api(app, version='1.0', title='Queue Management API', description='API for managing queue system')

# --- Database Models ---

class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    subcategories = relationship("Subcategory", back_populates="category")
    services = relationship("Service", back_populates="category")

class Subcategory(Base):
    __tablename__ = 'subcategories'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    category = relationship("Category", back_populates="subcategories")
    services = relationship("Service", back_populates="subcategory")

class Service(Base):
    __tablename__ = 'services'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    subcategory_id = Column(Integer, ForeignKey('subcategories.id'), nullable=True)
    estimated_time = Column(Integer)
    category = relationship("Category", back_populates="services")
    subcategory = relationship("Subcategory", back_populates="services")
    tickets = relationship("Ticket", back_populates="service")

class Ticket(Base):
    __tablename__ = 'tickets'
    id = Column(Integer, primary_key=True)
    number = Column(String, nullable=False, unique=True)
    service_id = Column(Integer, ForeignKey('services.id'), nullable=False)
    client_telegram_chat_id = Column(String)
    status = Column(String, nullable=False, default='waiting')
    operator_id = Column(Integer, ForeignKey('operators.id'))
    created_at = Column(DateTime, default=func.now())
    called_at = Column(DateTime)
    finished_at = Column(DateTime)
    redirected_from_ticket_id = Column(Integer, ForeignKey('tickets.id'))
    priority = Column(Integer, default=0)
    service = relationship("Service", back_populates="tickets")
    operator = relationship("Operator")

class Operator(Base):
    __tablename__ = 'operators'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    operator_number = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    telegram_chat_id = Column(String, unique=True)
    theme_preference = Column(String, default='light')

class OperatorServiceAssignment(Base):
    __tablename__ = 'operator_service_assignments'
    operator_id = Column(Integer, ForeignKey('operators.id'), primary_key=True)
    service_id = Column(Integer, ForeignKey('services.id'), primary_key=True)

class Admin(Base):
    __tablename__ = 'admins'
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    theme_preference = Column(String, default='light')

class DailyStatistics(Base):
    __tablename__ = 'daily_statistics'
    id = Column(Integer, primary_key=True)
    date = Column(String, nullable=False, unique=True)
    total_tickets = Column(Integer, default=0)
    finished_tickets = Column(Integer, default=0)
    cancelled_tickets = Column(Integer, default=0)
    redirected_tickets = Column(Integer, default=0)
    avg_wait_time = Column(Float, default=0)
    avg_service_time = Column(Float, default=0)

class OperatorStatistics(Base):
    __tablename__ = 'operator_statistics'
    id = Column(Integer, primary_key=True)
    operator_id = Column(Integer, ForeignKey('operators.id'), nullable=False)
    date = Column(String, nullable=False)
    called_tickets = Column(Integer, default=0)
    finished_tickets = Column(Integer, default=0)
    cancelled_tickets = Column(Integer, default=0)
    redirected_tickets = Column(Integer, default=0)
    avg_wait_time = Column(Float, default=0)
    avg_service_time = Column(Float, default=0)

class ServiceStatistics(Base):
    __tablename__ = 'service_statistics'
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey('services.id'), nullable=False)
    date = Column(String, nullable=False)
    called_tickets = Column(Integer, default=0)
    finished_tickets = Column(Integer, default=0)
    cancelled_tickets = Column(Integer, default=0)
    redirected_tickets = Column(Integer, default=0)
    avg_wait_time = Column(Float, default=0)
    avg_service_time = Column(Float, default=0)

class MediaFile(Base):
    __tablename__ = 'media_files'
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False, unique=True)
    filepath = Column(String, nullable=False)
    file_type = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=func.now())

class Language(Base):
    __tablename__ = 'languages'
    id = Column(Integer, primary_key=True)
    lang_code = Column(String, nullable=False, unique=True)
    display_name = Column(String, nullable=False)

class Webhook(Base):
    __tablename__ = 'webhooks'
    id = Column(Integer, primary_key=True)
    event_type = Column(String, nullable=False)
    url = Column(String, nullable=False)

class ChatMessage(Base):
    __tablename__ = 'chat_messages'
    id = Column(Integer, primary_key=True)
    ticket_number = Column(String, ForeignKey('tickets.number'), nullable=False)
    sender_type = Column(String, nullable=False)
    sender_id = Column(String)
    content = Column(Text)
    file_url = Column(String)
    file_type = Column(String)
    created_at = Column(DateTime, default=func.now())

# Initialize database
def init_db():
    Base.metadata.create_all(engine)
    db_session = SessionLocal()
    try:
        admin_count = db_session.query(Admin).count()
        if admin_count == 0:
            print("\n=== Admin Setup ===")
            while True:
                username = input("Enter admin username: ").strip()
                if not username:
                    print("Username cannot be empty.")
                    continue
                password = input("Enter admin password: ").strip()
                if not password:
                    print("Password cannot be empty.")
                    continue
                confirm = input("Confirm password: ").strip()
                if password != confirm:
                    print("Passwords do not match.")
                    continue
                break
            hashed_password = generate_password_hash(password)
            admin = Admin(username=username, password_hash=hashed_password)
            db_session.add(admin)
            db_session.commit()
            print(f"Admin '{username}' created successfully!\n")
    finally:
        db_session.close()

# --- Helper Functions ---

def generate_ticket_number(category_id, subcategory_id, db_session):
    date_str = get_current_tashkent_time().strftime('%Y-%m-%d')
    count = db_session.query(Ticket).filter(
        Ticket.created_at >= date_str,
        Ticket.service_id.in_(
            db_session.query(Service.id).filter(
                Service.category_id == category_id,
                Service.subcategory_id == subcategory_id
            )
        )
    ).count() + 1
    return f"{category_id}-{subcategory_id or '0'}-{count:04d}"

@celery.task
def send_telegram_message_async(chat_id, message_text):
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not bot_token:
        logging.error("TELEGRAM_BOT_TOKEN not set.")
        return False, "Telegram bot token not configured."
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message_text, 'parse_mode': 'HTML'}
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        logging.info(f"Telegram message sent to {chat_id}: {message_text}")
        return True, "Message sent successfully."
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending Telegram message to {chat_id}: {e}")
        return False, f"Failed to send message: {e}"

def get_current_tashkent_time():
    return datetime.now(UZBEKISTAN_TIMEZONE)

def load_translations_from_file():
    try:
        with open('translations.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error("translations.json not found.")
        return {}

def trigger_webhook(event_type, payload):
    db_session = SessionLocal()
    try:
        webhooks = db_session.query(Webhook).filter(Webhook.event_type == event_type).all()
        for webhook in webhooks:
            try:
                response = requests.post(webhook.url, json=payload, timeout=5)
                response.raise_for_status()
                logging.info(f"Webhook for '{event_type}' sent to {webhook.url} successfully.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to send webhook for '{event_type}' to {webhook.url}: {e}")
    finally:
        db_session.close()

def update_statistics(date, operator_id=None, service_id=None, called_tickets=0, finished_tickets=0, cancelled_tickets=0, redirected_tickets=0, wait_time=0, service_time=0):
    db_session = SessionLocal()
    try:
        daily_stat = db_session.query(DailyStatistics).filter(DailyStatistics.date == date).first()
        if not daily_stat:
            daily_stat = DailyStatistics(date=date)
            db_session.add(daily_stat)
        daily_stat.total_tickets += (called_tickets + finished_tickets + cancelled_tickets + redirected_tickets)
        daily_stat.finished_tickets += finished_tickets
        daily_stat.cancelled_tickets += cancelled_tickets
        daily_stat.redirected_tickets += redirected_tickets
        if called_tickets:
            daily_stat.avg_wait_time = ((daily_stat.avg_wait_time * (daily_stat.called_tickets or 1)) + wait_time) / (daily_stat.called_tickets + called_tickets or 1)
        if finished_tickets:
            daily_stat.avg_service_time = ((daily_stat.avg_service_time * (daily_stat.finished_tickets or 1)) + service_time) / (daily_stat.finished_tickets + finished_tickets or 1)
        daily_stat.called_tickets = (daily_stat.called_tickets or 0) + called_tickets

        if operator_id:
            op_stat = db_session.query(OperatorStatistics).filter(OperatorStatistics.operator_id == operator_id, OperatorStatistics.date == date).first()
            if not op_stat:
                op_stat = OperatorStatistics(operator_id=operator_id, date=date)
                db_session.add(op_stat)
            op_stat.called_tickets += called_tickets
            op_stat.finished_tickets += finished_tickets
            op_stat.cancelled_tickets += cancelled_tickets
            op_stat.redirected_tickets += redirected_tickets
            if called_tickets:
                op_stat.avg_wait_time = ((op_stat.avg_wait_time * (op_stat.called_tickets or 1)) + wait_time) / (op_stat.called_tickets + called_tickets or 1)
            if finished_tickets:
                op_stat.avg_service_time = ((op_stat.avg_service_time * (op_stat.finished_tickets or 1)) + service_time) / (op_stat.finished_tickets + finished_tickets or 1)

        if service_id:
            svc_stat = db_session.query(ServiceStatistics).filter(ServiceStatistics.service_id == service_id, ServiceStatistics.date == date).first()
            if not svc_stat:
                svc_stat = ServiceStatistics(service_id=service_id, date=date)
                db_session.add(svc_stat)
            svc_stat.called_tickets += called_tickets
            svc_stat.finished_tickets += finished_tickets
            svc_stat.cancelled_tickets += cancelled_tickets
            svc_stat.redirected_tickets += redirected_tickets
            if called_tickets:
                svc_stat.avg_wait_time = ((svc_stat.avg_wait_time * (svc_stat.called_tickets or 1)) + wait_time) / (svc_stat.called_tickets + called_tickets or 1)
            if finished_tickets:
                svc_stat.avg_service_time = ((svc_stat.avg_service_time * (svc_stat.finished_tickets or 1)) + service_time) / (svc_stat.finished_tickets + finished_tickets or 1)

        db_session.commit()
    except Exception as e:
        db_session.rollback()
        logging.error(f"Error updating statistics for date {date}: {e}")
    finally:
        db_session.close()

# --- Authentication Decorators ---

def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            logging.warning("Unauthorized admin access attempt.")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def operator_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'operator_id' not in session:
            logging.warning("Unauthorized operator access attempt.")
            return redirect(url_for('operator_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Error Handlers ---

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": str(e)}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized access"}), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden"}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    logging.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html', SERVER_URL=SERVER_URL)

@app.route('/operator_login')
@limiter.limit("10 per minute")
def operator_login():
    return render_template('login.html', SERVER_URL=SERVER_URL)

@app.route('/admin_login')
@limiter.limit("10 per minute")
def admin_login():
    return render_template('admin_login.html', SERVER_URL=SERVER_URL)

@app.route('/operator/<int:operator_id>')
@operator_required
def operator_panel(operator_id):
    if session.get('operator_id') != operator_id:
        abort(403)
    return render_template('operator.html', operator_id=operator_id, SERVER_URL=SERVER_URL)

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', SERVER_URL=SERVER_URL)

@app.route('/display')
def display_board():
    return render_template('display.html', SERVER_URL=SERVER_URL)

@app.route('/tablet/<int:operator_id>')
def operator_tablet(operator_id):
    return render_template('tablet.html', operator_id=operator_id, SERVER_URL=SERVER_URL)

@app.route('/status/<string:ticket_number>')
def ticket_status(ticket_number):
    db_session = SessionLocal()
    try:
        ticket = db_session.query(Ticket).filter(Ticket.number == ticket_number).first()
        if not ticket:
            abort(404, description="Ticket not found.")
        return render_template('status.html', ticket_number=ticket_number, SERVER_URL=SERVER_URL)
    finally:
        db_session.close()

@app.route('/chat/<string:ticket_number>')
def chat_interface(ticket_number):
    db_session = SessionLocal()
    try:
        ticket = db_session.query(Ticket).filter(Ticket.number == ticket_number).first()
        if not ticket:
            abort(404, description="Ticket not found.")
        return render_template('chat.html', ticket_number=ticket_number, SERVER_URL=SERVER_URL)
    finally:
        db_session.close()

@app.route('/admin/categories')
@admin_required
def admin_categories():
    return render_template('admin_categories.html', SERVER_URL=SERVER_URL)

@app.route('/admin/services')
@admin_required
def admin_services():
    return render_template('admin_services.html', SERVER_URL=SERVER_URL)

@app.route('/admin/operators')
@admin_required
def admin_operators():
    return render_template('admin_operators.html', SERVER_URL=SERVER_URL)

@app.route('/admin/media')
@admin_required
def admin_media():
    return render_template('admin_media.html', SERVER_URL=SERVER_URL)

@app.route('/admin/translations')
@admin_required
def admin_translations():
    return render_template('admin_translations.html', SERVER_URL=SERVER_URL)

@app.route('/admin/languages')
@admin_required
def admin_languages():
    return render_template('admin_languages.html', SERVER_URL=SERVER_URL)

@app.route('/admin/webhooks')
@admin_required
def admin_webhooks():
    return render_template('admin_webhooks.html', SERVER_URL=SERVER_URL)

@app.route('/admin/statistics')
@admin_required
def admin_statistics():
    return render_template('admin_statistics.html', SERVER_URL=SERVER_URL)

@app.route('/forgot_password')
def forgot_password():
    role = request.args.get('role', 'operator')
    return render_template('forgot_password.html', SERVER_URL=SERVER_URL, role=role)

# --- API Endpoints ---

ns = api.namespace('api', description='Queue Management Operations')

# Models for Swagger
ticket_model = api.model('Ticket', {
    'service_id': fields.Integer(required=True, description='Service ID'),
    'client_telegram_chat_id': fields.String(description='Client Telegram Chat ID')
})
category_model = api.model('Category', {
    'name': fields.String(required=True, description='Category name')
})
subcategory_model = api.model('Subcategory', {
    'name': fields.String(required=True, description='Subcategory name'),
    'category_id': fields.Integer(required=True, description='Category ID')
})
service_model = api.model('Service', {
    'name': fields.String(required=True, description='Service name'),
    'category_id': fields.Integer(required=True, description='Category ID'),
    'subcategory_id': fields.Integer(description='Subcategory ID'),
    'estimated_time': fields.Integer(description='Estimated time in minutes')
})
operator_model = api.model('Operator', {
    'name': fields.String(required=True, description='Operator name'),
    'operator_number': fields.String(required=True, description='Operator number'),
    'password': fields.String(required=True, description='Password'),
    'telegram_chat_id': fields.String(description='Telegram Chat ID'),
    'assigned_services': fields.List(fields.Integer, description='List of service IDs')
})
operator_login_model = api.model('OperatorLogin', {
    'username': fields.String(required=True, description='Operator number'),
    'password': fields.String(required=True, description='Password')
})
admin_login_model = api.model('AdminLogin', {
    'username': fields.String(required=True, description='Admin username'),
    'password': fields.String(required=True, description='Password')
})
webhook_model = api.model('Webhook', {
    'event_type': fields.String(required=True, description='Event type'),
    'url': fields.String(required=True, description='Webhook URL')
})
language_model = api.model('Language', {
    'lang_code': fields.String(required=True, description='Language code'),
    'display_name': fields.String(required=True, description='Display name')
})
media_model = api.model('Media', {
    'file': fields.Raw(required=True, description='File to upload')
})
chat_message_model = api.model('ChatMessage', {
    'ticket_number': fields.String(required=True, description='Ticket number'),
    'sender_type': fields.String(required=True, description='Sender type (client/operator)'),
    'sender_id': fields.String(description='Sender ID'),
    'content': fields.String(description='Message content'),
    'file_url': fields.String(description='File URL'),
    'file_type': fields.String(description='File type')
})

@ns.route('/categories')
class Categories(Resource):
    @api.doc(description='Get all categories with pagination')
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            categories = db_session.query(Category).order_by(Category.name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Category).count()
            return {
                "categories": [{"id": c.id, "name": c.name} for c in categories],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/categories/<int:category_id>/subcategories')
class Subcategories(Resource):
    @api.doc(description='Get subcategories for a category')
    def get(self, category_id):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            subcategories = db_session.query(Subcategory).filter(Subcategory.category_id == category_id).order_by(Subcategory.name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Subcategory).filter(Subcategory.category_id == category_id).count()
            return {
                "subcategories": [{"id": s.id, "name": s.name, "category_id": s.category_id} for s in subcategories],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/subcategories/<int:subcategory_id>/services')
class SubcategoryServices(Resource):
    @api.doc(description='Get services for a subcategory')
    def get(self, subcategory_id):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            services = db_session.query(Service).filter(Service.subcategory_id == subcategory_id).order_by(Service.name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Service).filter(Service.subcategory_id == subcategory_id).count()
            return {
                "services": [{"id": s.id, "name": s.name, "category_id": s.category_id, "subcategory_id": s.subcategory_id, "estimated_time": s.estimated_time} for s in services],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/categories/<int:category_id>/services')
class CategoryServices(Resource):
    @api.doc(description='Get services for a category')
    def get(self, category_id):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            services = db_session.query(Service).filter(Service.category_id == category_id).order_by(Service.name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Service).filter(Service.category_id == category_id).count()
            return {
                "services": [{"id": s.id, "name": s.name, "category_id": s.category_id, "subcategory_id": s.subcategory_id, "estimated_time": s.estimated_time} for s in services],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/ticket')
class TicketResource(Resource):
    @api.expect(ticket_model)
    @api.doc(description='Create a new ticket')
    def post(self):
        data = request.get_json()
        service_id = data.get('service_id')
        client_telegram_chat_id = data.get('client_telegram_chat_id')

        if not service_id:
            api.abort(400, "Service ID is required")

        db_session = SessionLocal()
        try:
            service = db_session.query(Service).filter(Service.id == service_id).first()
            if not service:
                api.abort(404, "Service not found")

            ticket_number = generate_ticket_number(service.category_id, service.subcategory_id, db_session)
            valid_until = get_current_tashkent_time() + timedelta(minutes=service.estimated_time * 2 if service.estimated_time else 30)

            ticket = Ticket(
                number=ticket_number,
                service_id=service_id,
                client_telegram_chat_id=client_telegram_chat_id,
                status='waiting',
                created_at=get_current_tashkent_time()
            )
            db_session.add(ticket)
            db_session.commit()

            qr_data = f"{BASE_URL_FOR_QR}/status/{ticket_number}"
            qr_img = qrcode.make(qr_data)
            qr_filename = f"qr_{ticket_number}.png"
            qr_filepath = os.path.join(app.root_path, 'static', 'qrcodes', qr_filename)
            os.makedirs(os.path.dirname(qr_filepath), exist_ok=True)
            qr_img.save(qr_filepath)
            qr_code_url = f"{BASE_URL_FOR_QR}/static/qrcodes/{qr_filename}"

            trigger_webhook('new_ticket', {
                'ticket_number': ticket_number,
                'service_id': service_id,
                'client_telegram_chat_id': client_telegram_chat_id,
                'created_at': get_current_tashkent_time().isoformat(),
                'status': 'waiting'
            })

            if client_telegram_chat_id:
                message = (
                    f"Sizning navbat raqamingiz: <b>{ticket_number}</b>\n"
                    f"Xizmat: <b>{service.name}</b>\n"
                    f"Taxminiy kutish vaqti: <b>{service.estimated_time or 30} min</b>\n"
                    f"Navbat holatini tekshirish: {BASE_URL_FOR_QR}/status/{ticket_number}\n"
                    f"Amal qilish muddati: {valid_until.strftime('%Y-%m-%d %H:%M')}"
                )
                send_telegram_message_async.delay(client_telegram_chat_id, message)

            return {
                "message": "Ticket created successfully",
                "ticket_number": ticket_number,
                "qr_code_url": qr_code_url,
                "valid_until": valid_until.isoformat()
            }, 201
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error creating ticket: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/queue')
class Queue(Resource):
    @api.doc(description='Get current queue')
    def get(self):
        db_session = SessionLocal()
        try:
            tickets = db_session.query(Ticket.number, Ticket.status, Operator.name.label('operator_name')).\
                outerjoin(Operator, Ticket.operator_id == Operator.id).\
                filter(Ticket.status.in_(['waiting', 'called'])).\
                order_by(
                    func.case(
                        (Ticket.status == 'called', 1),
                        (Ticket.status == 'waiting', 2),
                        else_=3
                    ),
                    Ticket.priority.desc(),
                    Ticket.created_at.asc()
                ).all()
            return [{"number": t.number, "status": t.status, "operator_name": t.operator_name} for t in tickets]
        finally:
            db_session.close()

@ns.route('/tablet/<int:operator_id>/current_ticket')
class TabletCurrentTicket(Resource):
    @api.doc(description='Get current ticket for operator tablet')
    def get(self, operator_id):
        db_session = SessionLocal()
        try:
            ticket = db_session.query(Ticket).filter(Ticket.operator_id == operator_id, Ticket.status == 'called').first()
            return {"ticket_number": ticket.number if ticket else None}
        finally:
            db_session.close()

@ns.route('/operator_login')
class OperatorLogin(Resource):
    @api.expect(operator_login_model)
    @api.doc(description='Operator login')
    @limiter.limit("10 per minute")
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        db_session = SessionLocal()
        try:
            operator = db_session.query(Operator).filter(Operator.operator_number == username).first()
            if operator and check_password_hash(operator.password_hash, password):
                session['operator_id'] = operator.id
                session['operator_name'] = operator.name
                session['role'] = 'operator'
                logging.info(f"Operator {username} logged in.")
                return {
                    "message": "Login successful",
                    "operator_id": operator.id,
                    "theme_preference": operator.theme_preference
                }, 200
            logging.warning(f"Failed login attempt for operator: {username}")
            api.abort(401, "Invalid credentials")
        finally:
            db_session.close()

@ns.route('/operator_logout')
class OperatorLogout(Resource):
    @api.doc(description='Operator logout')
    def get(self):
        session.pop('operator_id', None)
        session.pop('operator_name', None)
        session.pop('role', None)
        logging.info("Operator logged out.")
        return redirect(url_for('operator_login'))

@ns.route('/admin_login')
class AdminLogin(Resource):
    @api.expect(admin_login_model)
    @api.doc(description='Admin login')
    @limiter.limit("10 per minute")
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        db_session = SessionLocal()
        try:
            admin = db_session.query(Admin).filter(Admin.username == username).first()
            if admin and check_password_hash(admin.password_hash, password):
                session['admin_id'] = admin.id
                session['admin_username'] = admin.username
                session['role'] = 'admin'
                logging.info(f"Admin {username} logged in.")
                return {
                    "message": "Login successful",
                    "admin_id": admin.id,
                    "theme_preference": admin.theme_preference
                }, 200
            logging.warning(f"Failed login attempt for admin: {username}")
            api.abort(401, "Invalid credentials")
        finally:
            db_session.close()

@ns.route('/admin_logout')
class AdminLogout(Resource):
    @api.doc(description='Admin logout')
    def get(self):
        session.pop('admin_id', None)
        session.pop('admin_username', None)
        session.pop('role', None)
        logging.info("Admin logged out.")
        return redirect(url_for('admin_login'))

@ns.route('/operator/<int:operator_id>/tickets')
class OperatorTickets(Resource):
    @api.doc(description='Get tickets for an operator')
    @operator_required
    def get(self, operator_id):
        if session.get('operator_id') != operator_id:
            api.abort(403)
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            tickets = db_session.query(Ticket.id, Ticket.number, Ticket.status, Ticket.priority, Ticket.created_at, Service.name.label('service_name')).\
                join(Service, Ticket.service_id == Service.id).\
                filter((Ticket.operator_id == operator_id) | (Ticket.status == 'waiting')).\
                order_by(
                    func.case(
                        (Ticket.status == 'called', 1),
                        (Ticket.status == 'waiting', 2),
                        else_=3
                    ),
                    Ticket.priority.desc(),
                    Ticket.created_at.asc()
                ).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Ticket).filter((Ticket.operator_id == operator_id) | (Ticket.status == 'waiting')).count()
            return {
                "tickets": [{"id": t.id, "number": t.number, "status": t.status, "priority": t.priority, "created_at": t.created_at.isoformat(), "service_name": t.service_name} for t in tickets],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/operator/<int:operator_id>/call_next')
class CallNextTicket(Resource):
    @api.doc(description='Operator calls next ticket')
    @operator_required
    def post(self, operator_id):
        if session.get('operator_id') != operator_id:
            api.abort(403)
        db_session = SessionLocal()
        try:
            current_called_ticket = db_session.query(Ticket).filter(Ticket.operator_id == operator_id, Ticket.status == 'called').first()
            if current_called_ticket:
                api.abort(400, "Operator already has a ticket in 'called' status.")

            assigned_services = db_session.query(OperatorServiceAssignment.service_id).filter(OperatorServiceAssignment.operator_id == operator_id).all()
            assigned_service_ids = [s.service_id for s in assigned_services]

            query = db_session.query(Ticket).filter(Ticket.status == 'waiting')
            if assigned_service_ids:
                query = query.filter(Ticket.service_id.in_(assigned_service_ids))
            next_ticket = query.order_by(Ticket.priority.desc(), Ticket.created_at.asc()).first()

            if next_ticket:
                now = get_current_tashkent_time()
                next_ticket.status = 'called'
                next_ticket.operator_id = operator_id
                next_ticket.called_at = now
                db_session.commit()

                wait_time_seconds = (now - next_ticket.created_at).total_seconds()
                update_statistics(
                    date=now.strftime('%Y-%m-%d'),
                    operator_id=operator_id,
                    service_id=None,
                    called_tickets=1,
                    wait_time=wait_time_seconds
                )

                socketio.emit('update_queue', {'ticket': next_ticket.number, 'operator_id': operator_id})
                logging.info(f"Operator {operator_id} called ticket {next_ticket.number}")

                ticket_info = db_session.query(Ticket.client_telegram_chat_id, Service.name.label('service_name')).\
                    join(Service, Ticket.service_id == Service.id).\
                    filter(Ticket.id == next_ticket.id).first()
                if ticket_info and ticket_info.client_telegram_chat_id:
                    message = (
                        f"Sizning <b>{ticket_info.service_name}</b> xizmati boʻyicha navbat raqamingiz <b>{next_ticket.number}</b> chaqirildi!\n"
                        f"Iltimos, operatorga yondashing."
                    )
                    send_telegram_message_async.delay(ticket_info.client_telegram_chat_id, message)

                trigger_webhook('ticket_called', {
                    'ticket_number': next_ticket.number,
                    'operator_id': operator_id,
                    'called_at': now.isoformat()
                })

                return {"message": "Ticket called", "ticket_number": next_ticket.number}, 200
            api.abort(404, "No waiting tickets available.")
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error calling next ticket for operator {operator_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/operator/<int:operator_id>/finish_ticket')
class FinishTicket(Resource):
    @api.doc(description='Operator finishes current ticket')
    @operator_required
    def post(self, operator_id):
        if session.get('operator_id') != operator_id:
            api.abort(403)
        data = request.get_json()
        ticket_number = data.get('ticket')
        if not ticket_number:
            api.abort(400, "Ticket number is required")
        db_session = SessionLocal()
        try:
            ticket = db_session.query(Ticket).filter(Ticket.number == ticket_number, Ticket.operator_id == operator_id, Ticket.status == 'called').first()
            if not ticket:
                api.abort(404, "Ticket not found or not in 'called' status for this operator.")

            now = get_current_tashkent_time()
            ticket.status = 'finished'
            ticket.finished_at = now
            db_session.commit()

            service_time_seconds = (now - ticket.called_at).total_seconds()
            update_statistics(
                date=now.strftime('%Y-%m-%d'),
                operator_id=operator_id,
                service_id=ticket.service_id,
                finished_tickets=1,
                service_time=service_time_seconds
            )

            socketio.emit('remove_ticket', {'ticket': ticket_number, 'operator_id': operator_id})
            logging.info(f"Operator {operator_id} finished ticket {ticket_number}")

            if ticket.client_telegram_chat_id:
                message = (
                    f"Sizning navbat raqamingiz <b>{ticket_number}</b> boʻyicha xizmat tugallandi.\n"
                    f"Fikr-mulohazalaringizni qoldirishingiz mumkin: {BASE_URL_FOR_QR}/feedback/{ticket_number}"
                )
                send_telegram_message_async.delay(ticket.client_telegram_chat_id, message)

            trigger_webhook('ticket_finished', {
                'ticket_number': ticket_number,
                'operator_id': operator_id,
                'finished_at': now.isoformat()
            })

            return {"message": "Ticket finished"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error finishing ticket {ticket_number} for operator {operator_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/operator/<int:operator_id>/cancel_ticket')
class CancelTicket(Resource):
    @api.doc(description='Operator cancels current ticket')
    @operator_required
    def post(self, operator_id):
        if session.get('operator_id') != operator_id:
            api.abort(403)
        data = request.get_json()
        ticket_number = data.get('ticket')
        if not ticket_number:
            api.abort(400, "Ticket number is required")
        db_session = SessionLocal()
        try:
            ticket = db_session.query(Ticket).filter(Ticket.number == ticket_number, Ticket.operator_id == operator_id, Ticket.status == 'called').first()
            if not ticket:
                api.abort(404, "Ticket not found or not in 'called' status for this operator.")

            now = get_current_tashkent_time()
            ticket.status = 'cancelled'
            ticket.finished_at = now
            db_session.commit()

            update_statistics(
                date=now.strftime('%Y-%m-%d'),
                operator_id=operator_id,
                service_id=ticket.service_id,
                cancelled_tickets=1
            )

            socketio.emit('remove_ticket', {'ticket': ticket_number, 'operator_id': operator_id})
            logging.info(f"Operator {operator_id} cancelled ticket {ticket_number}")

            if ticket.client_telegram_chat_id:
                message = (
                    f"Sizning <b>{ticket_number}</b> navbat raqamingiz bekor qilindi.\n"
                    f"Iltimos, qayta roʻyxatdan oʻting yoki operatorga murojaat qiling."
                )
                send_telegram_message_async.delay(ticket.client_telegram_chat_id, message)

            trigger_webhook('ticket_cancelled', {
                'ticket_number': ticket_number,
                'operator_id': operator_id,
                'cancelled_at': now.isoformat()
            })

            return {"message": "Ticket cancelled"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error cancelling ticket {ticket_number} for operator {operator_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/operator/<int:operator_id>/redirect_ticket')
class RedirectTicket(Resource):
    @api.doc(description='Operator redirects a ticket')
    @operator_required
    def post(self, operator_id):
        if session.get('operator_id') != operator_id:
            api.abort(403)
        data = request.get_json()
        ticket_number = data.get('ticket_number')
        new_service_id = data.get('new_service_id')
        new_operator_id = data.get('new_operator_id')

        if not ticket_number or not new_service_id:
            api.abort(400, "Ticket number and new service ID are required")

        db_session = SessionLocal()
        try:
            ticket = db_session.query(Ticket).filter(Ticket.number == ticket_number, Ticket.operator_id == operator_id, Ticket.status == 'called').first()
            if not ticket:
                api.abort(404, "Ticket not found or not in 'called' status for this operator.")

            now = get_current_tashkent_time()
            ticket.status = 'redirected'
            ticket.finished_at = now

            new_service = db_session.query(Service).filter(Service.id == new_service_id).first()
            if not new_service:
                api.abort(404, "New service not found")

            new_ticket_number = generate_ticket_number(new_service.category_id, new_service.subcategory_id, db_session)
            new_ticket = Ticket(
                number=new_ticket_number,
                service_id=new_service_id,
                client_telegram_chat_id=ticket.client_telegram_chat_id,
                status='waiting',
                created_at=now,
                redirected_from_ticket_id=ticket.id,
                operator_id=new_operator_id,
                priority=ticket.priority
            )
            db_session.add(new_ticket)
            db_session.commit()

            update_statistics(
                date=now.strftime('%Y-%m-%d'),
                operator_id=operator_id,
                service_id=ticket.service_id,
                redirected_tickets=1
            )

            socketio.emit('remove_ticket', {'ticket': ticket_number, 'operator_id': operator_id})
            socketio.emit('update_queue', {'ticket': new_ticket_number, 'operator_id': new_operator_id or 'N/A'})
            logging.info(f"Operator {operator_id} redirected ticket {ticket_number} to new ticket {new_ticket_number}")

            if ticket.client_telegram_chat_id:
                new_service_name = new_service.name
                message = (
                    f"Sizning navbat raqamingiz <b>{ticket_number}</b> boshqa xizmatga yoʻnaltirildi.\n"
                    f"Yangi navbat raqamingiz: <b>{new_ticket_number}</b> (Xizmat: {new_service_name}).\n"
                    f"Navbat holatini tekshirish: {BASE_URL_FOR_QR}/status/{new_ticket_number}"
                )
                send_telegram_message_async.delay(ticket.client_telegram_chat_id, message)

            trigger_webhook('ticket_redirected', {
                'original_ticket_number': ticket_number,
                'new_ticket_number': new_ticket_number,
                'operator_id': operator_id,
                'new_service_id': new_service_id,
                'new_operator_id': new_operator_id,
                'redirected_at': now.isoformat()
            })

            return {"message": "Ticket redirected successfully", "new_ticket_number": new_ticket_number}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error redirecting ticket {ticket_number} for operator {operator_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/chat_history/<string:ticket_number>')
class ChatHistory(Resource):
    @api.doc(description='Get chat history for a ticket')
    def get(self, ticket_number):
        db_session = SessionLocal()
        try:
            messages = db_session.query(ChatMessage).filter(ChatMessage.ticket_number == ticket_number).order_by(ChatMessage.created_at.asc()).all()
            return [{
                "sender_type": m.sender_type,
                "content": m.content,
                "file_url": m.file_url,
                "file_type": m.file_type,
                "created_at": m.created_at.isoformat()
            } for m in messages]
        finally:
            db_session.close()

@ns.route('/chat_upload')
class ChatUpload(Resource):
    @api.expect(media_model)
    @api.doc(description='Upload file for chat')
    def post(self):
        if 'file' not in request.files:
            api.abort(400, "No file part")
        file = request.files['file']
        if file.filename == '':
            api.abort(400, "No selected file")
        if file:
            filename = secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(MEDIA_FOLDER, unique_filename)
            file.save(filepath)

            file_type = 'document'
            if file_extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']:
                file_type = 'image'
            elif file_extension in ['mp4', 'webm', 'ogg']:
                file_type = 'video'
            elif file_extension in ['mp3', 'wav', 'aac']:
                file_type = 'audio'

            file_url = f"{BASE_URL_FOR_QR}/{filepath}"
            logging.info(f"File uploaded: {file_url} with type {file_type}")
            return {"message": "File uploaded successfully", "file_url": file_url, "file_type": file_type}, 200
        api.abort(500, "File upload failed")

@ns.route('/admin/categories')
class AdminCategories(Resource):
    @api.doc(description='Get all categories for admin')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            categories = db_session.query(Category).order_by(Category.name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Category).count()
            return {
                "categories": [{"id": c.id, "name": c.name} for c in categories],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

    @api.expect(category_model)
    @api.doc(description='Add a new category')
    @admin_required
    def post(self):
        data = request.get_json()
        name = data.get('name')
        if not name:
            api.abort(400, "Category name is required")
        db_session = SessionLocal()
        try:
            category = Category(name=name)
            db_session.add(category)
            db_session.commit()
            logging.info(f"Admin added category: {name}")
            return {"message": "Category added successfully"}, 201
        except Exception as e:
            db_session.rollback()
            if "unique constraint" in str(e).lower():
                api.abort(409, "Category with this name already exists")
            logging.error(f"Error adding category: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/categories/<int:category_id>')
class AdminCategory(Resource):
    @api.expect(category_model)
    @api.doc(description='Update a category')
    @admin_required
    def put(self, category_id):
        data = request.get_json()
        name = data.get('name')
        if not name:
            api.abort(400, "Category name is required")
        db_session = SessionLocal()
        try:
            category = db_session.query(Category).filter(Category.id == category_id).first()
            if not category:
                api.abort(404, "Category not found")
            category.name = name
            db_session.commit()
            logging.info(f"Admin updated category {category_id} to: {name}")
            return {"message": "Category updated successfully"}, 200
        except Exception as e:
            db_session.rollback()
            if "unique constraint" in str(e).lower():
                api.abort(409, "Category with this name already exists")
            logging.error(f"Error updating category {category_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

    @api.doc(description='Delete a category')
    @admin_required
    def delete(self, category_id):
        db_session = SessionLocal()
        try:
            category = db_session.query(Category).filter(Category.id == category_id).first()
            if not category:
                api.abort(404, "Category not found")
            db_session.delete(category)
            db_session.commit()
            logging.info(f"Admin deleted category: {category_id}")
            return {"message": "Category deleted successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error deleting category {category_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/subcategories')
class AdminSubcategories(Resource):
    @api.doc(description='Get all subcategories for admin')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            subcategories = db_session.query(Subcategory, Category.name.label('category_name')).\
                join(Category, Subcategory.category_id == Category.id).\
                order_by(Category.name.asc(), Subcategory.name.asc()).\
                offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Subcategory).count()
            return {
                "subcategories": [{"id": s.Subcategory.id, "name": s.Subcategory.name, "category_id": s.Subcategory.category_id, "category_name": s.category_name} for s in subcategories],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

    @api.expect(subcategory_model)
    @api.doc(description='Add a new subcategory')
    @admin_required
    def post(self):
        data = request.get_json()
        name = data.get('name')
        category_id = data.get('category_id')
        if not name or not category_id:
            api.abort(400, "Subcategory name and category ID are required")
        db_session = SessionLocal()
        try:
            subcategory = Subcategory(name=name, category_id=category_id)
            db_session.add(subcategory)
            db_session.commit()
            logging.info(f"Admin added subcategory: {name}")
            return {"message": "Subcategory added successfully"}, 201
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error adding subcategory: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/subcategories/<int:subcategory_id>')
class AdminSubcategory(Resource):
    @api.expect(subcategory_model)
    @api.doc(description='Update a subcategory')
    @admin_required
    def put(self, subcategory_id):
        data = request.get_json()
        name = data.get('name')
        category_id = data.get('category_id')
        if not name or not category_id:
            api.abort(400, "Subcategory name and category ID are required")
        db_session = SessionLocal()
        try:
            subcategory = db_session.query(Subcategory).filter(Subcategory.id == subcategory_id).first()
            if not subcategory:
                api.abort(404, "Subcategory not found")
            subcategory.name = name
            subcategory.category_id = category_id
            db_session.commit()
            logging.info(f"Admin updated subcategory {subcategory_id}")
            return {"message": "Subcategory updated successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error updating subcategory {subcategory_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

    @api.doc(description='Delete a subcategory')
    @admin_required
    def delete(self, subcategory_id):
        db_session = SessionLocal()
        try:
            subcategory = db_session.query(Subcategory).filter(Subcategory.id == subcategory_id).first()
            if not subcategory:
                api.abort(404, "Subcategory not found")
            db_session.delete(subcategory)
            db_session.commit()
            logging.info(f"Admin deleted subcategory: {subcategory_id}")
            return {"message": "Subcategory deleted successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error deleting subcategory {subcategory_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/services')
class AdminServices(Resource):
    @api.doc(description='Get all services for admin')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            services = db_session.query(Service, Category.name.label('category_name'), Subcategory.name.label('subcategory_name')).\
                join(Category, Service.category_id == Category.id).\
                outerjoin(Subcategory, Service.subcategory_id == Subcategory.id).\
                order_by(Category.name.asc(), Subcategory.name.asc(), Service.name.asc()).\
                offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Service).count()
            return {
                "services": [{
                    "id": s.Service.id,
                    "name": s.Service.name,
                    "category_id": s.Service.category_id,
                    "subcategory_id": s.Service.subcategory_id,
                    "estimated_time": s.Service.estimated_time,
                    "category_name": s.category_name,
                    "subcategory_name": s.subcategory_name
                } for s in services],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

    @api.expect(service_model)
    @api.doc(description='Add a new service')
    @admin_required
    def post(self):
        data = request.get_json()
        name = data.get('name')
        category_id = data.get('category_id')
        subcategory_id = data.get('subcategory_id')
        estimated_time = data.get('estimated_time')
        if not name or not category_id:
            api.abort(400, "Service name and category ID are required")
        db_session = SessionLocal()
        try:
            service = Service(name=name, category_id=category_id, subcategory_id=subcategory_id, estimated_time=estimated_time)
            db_session.add(service)
            db_session.commit()
            logging.info(f"Admin added service: {name}")
            return {"message": "Service added successfully"}, 201
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error adding service: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/services/<int:service_id>')
class AdminService(Resource):
    @api.expect(service_model)
    @api.doc(description='Update a service')
    @admin_required
    def put(self, service_id):
        data = request.get_json()
        name = data.get('name')
        category_id = data.get('category_id')
        subcategory_id = data.get('subcategory_id')
        estimated_time = data.get('estimated_time')
        if not name or not category_id:
            api.abort(400, "Service name and category ID are required")
        db_session = SessionLocal()
        try:
            service = db_session.query(Service).filter(Service.id == service_id).first()
            if not service:
                api.abort(404, "Service not found")
            service.name = name
            service.category_id = category_id
            service.subcategory_id = subcategory_id
            service.estimated_time = estimated_time
            db_session.commit()
            logging.info(f"Admin updated service {service_id}")
            return {"message": "Service updated successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error updating service {service_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

    @api.doc(description='Delete a service')
    @admin_required
    def delete(self, service_id):
        db_session = SessionLocal()
        try:
            service = db_session.query(Service).filter(Service.id == service_id).first()
            if not service:
                api.abort(404, "Service not found")
            db_session.delete(service)
            db_session.commit()
            logging.info(f"Admin deleted service: {service_id}")
            return {"message": "Service deleted successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error deleting service {service_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/services')
class Services(Resource):
    @api.doc(description='Get services filtered by category or subcategory')
    def get(self):
        category_id = request.args.get('category_id')
        subcategory_id = request.args.get('subcategory_id')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            query = db_session.query(Service)
            if subcategory_id:
                query = query.filter(Service.subcategory_id == subcategory_id)
            elif category_id:
                query = query.filter(Service.category_id == category_id)
            services = query.order_by(Service.name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = query.count()
            return {
                "services": [{"id": s.id, "name": s.name, "category_id": s.category_id, "subcategory_id": s.subcategory_id, "estimated_time": s.estimated_time} for s in services],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/service/<int:service_id>/queue_info')
class ServiceQueueInfo(Resource):
    @api.doc(description='Get queue info for a service')
    def get(self, service_id):
        db_session = SessionLocal()
        try:
            queue_count = db_session.query(Ticket).filter(Ticket.service_id == service_id, Ticket.status == 'waiting').count()
            svc_stat = db_session.query(ServiceStatistics).filter(ServiceStatistics.service_id == service_id).order_by(ServiceStatistics.date.desc()).first()
            avg_time = svc_stat.avg_service_time if svc_stat and svc_stat.avg_service_time else None
            if not avg_time:
                service = db_session.query(Service).filter(Service.id == service_id).first()
                avg_time = service.estimated_time * 60 if service and service.estimated_time else 0
            estimated_wait = int(queue_count * (avg_time or 0))
            return {
                "queue_count": queue_count,
                "estimated_wait_seconds": estimated_wait
            }
        finally:
            db_session.close()

@ns.route('/admin/operators')
class AdminOperators(Resource):
    @api.doc(description='Get all operators for admin')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            operators = db_session.query(Operator).order_by(Operator.name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Operator).count()
            operators_list = []
            for op in operators:
                assigned_services = db_session.query(OperatorServiceAssignment.service_id).filter(OperatorServiceAssignment.operator_id == op.id).all()
                operators_list.append({
                    "id": op.id,
                    "name": op.name,
                    "operator_number": op.operator_number,
                    "telegram_chat_id": op.telegram_chat_id,
                    "theme_preference": op.theme_preference,
                    "assigned_services": [s.service_id for s in assigned_services]
                })
            return {
                "operators": operators_list,
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

    @api.expect(operator_model)
    @api.doc(description='Add a new operator')
    @admin_required
    def post(self):
        data = request.get_json()
        name = data.get('name')
        operator_number = data.get('operator_number')
        password = data.get('password')
        telegram_chat_id = data.get('telegram_chat_id')
        assigned_services = data.get('assigned_services', [])
        if not name or not operator_number or not password:
            api.abort(400, "Name, operator number, and password are required")
        db_session = SessionLocal()
        try:
            hashed_password = generate_password_hash(password)
            operator = Operator(name=name, operator_number=operator_number, password_hash=hashed_password, telegram_chat_id=telegram_chat_id)
            db_session.add(operator)
            db_session.flush()
            for service_id in assigned_services:
                db_session.add(OperatorServiceAssignment(operator_id=operator.id, service_id=service_id))
            db_session.commit()
            logging.info(f"Admin added operator: {name} ({operator_number})")
            return {"message": "Operator added successfully"}, 201
        except Exception as e:
            db_session.rollback()
            if "unique constraint" in str(e).lower():
                api.abort(409, "Operator number or Telegram ID already exists")
            logging.error(f"Error adding operator: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/operators/<int:operator_id>')
class AdminOperator(Resource):
    @api.expect(operator_model)
    @api.doc(description='Update an operator')
    @admin_required
    def put(self, operator_id):
        data = request.get_json()
        name = data.get('name')
        operator_number = data.get('operator_number')
        telegram_chat_id = data.get('telegram_chat_id')
        assigned_services = data.get('assigned_services', [])
        if not name or not operator_number:
            api.abort(400, "Name and operator number are required")
        db_session = SessionLocal()
        try:
            operator = db_session.query(Operator).filter(Operator.id == operator_id).first()
            if not operator:
                api.abort(404, "Operator not found")
            operator.name = name
            operator.operator_number = operator_number
            operator.telegram_chat_id = telegram_chat_id
            db_session.query(OperatorServiceAssignment).filter(OperatorServiceAssignment.operator_id == operator_id).delete()
            for service_id in assigned_services:
                db_session.add(OperatorServiceAssignment(operator_id=operator_id, service_id=service_id))
            db_session.commit()
            logging.info(f"Admin updated operator {operator_id}: {name} ({operator_number})")
            return {"message": "Operator updated successfully"}, 200
        except Exception as e:
            db_session.rollback()
            if "unique constraint" in str(e).lower():
                api.abort(409, "Operator number or Telegram ID already exists")
            logging.error(f"Error updating operator {operator_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

    @api.doc(description='Delete an operator')
    @admin_required
    def delete(self, operator_id):
        db_session = SessionLocal()
        try:
            operator = db_session.query(Operator).filter(Operator.id == operator_id).first()
            if not operator:
                api.abort(404, "Operator not found")
            db_session.delete(operator)
            db_session.commit()
            logging.info(f"Admin deleted operator: {operator_id}")
            return {"message": "Operator deleted successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error deleting operator {operator_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/operators/<int:operator_id>/reset_password')
class AdminOperatorResetPassword(Resource):
    @api.doc(description='Reset operator password')
    @admin_required
    def post(self, operator_id):
        db_session = SessionLocal()
        try:
            operator = db_session.query(Operator).filter(Operator.id == operator_id).first()
            if not operator:
                api.abort(404, "Operator not found")
            new_password = secrets.token_hex(16)
            hashed_password = generate_password_hash(new_password)
            operator.password_hash = hashed_password
            db_session.commit()

            if operator.telegram_chat_id:
                message = (
                    f"Sizning operator paneli parolingiz tiklandi.\n"
                    f"Yangi parol: <b>{new_password}</b>\n"
                    f"Iltimos, tizimga kirgandan soʻng parolingizni oʻzgartiring."
                )
                send_telegram_message_async.delay(operator.telegram_chat_id, message)
            else:
                logging.warning(f"Operator {operator_id} has no Telegram ID for password reset notification.")
                return {"message": "Password reset successfully, but operator has no Telegram ID for notification."}, 200

            logging.info(f"Admin reset password for operator {operator_id}")
            return {"message": "Password reset successfully. New password sent to operator via Telegram."}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error resetting password for operator {operator_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/operators')
class Operators(Resource):
    @api.doc(description='Get all operators')
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            operators = db_session.query(Operator).order_by(Operator.name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Operator).count()
            return {
                "operators": [{"id": o.id, "name": o.name, "operator_number": o.operator_number} for o in operators],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/admin/media')
class AdminMedia(Resource):
    @api.doc(description='Get all media files for admin')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            media_files = db_session.query(MediaFile).order_by(MediaFile.uploaded_at.desc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(MediaFile).count()
            return {
                "media_files": [{
                    "id": m.id,
                    "filename": m.filename,
                    "file_url": f"{BASE_URL_FOR_QR}/{m.filepath}",
                    "file_type": m.file_type,
                    "uploaded_at": m.uploaded_at.isoformat()
                } for m in media_files],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

    @api.expect(media_model)
    @api.doc(description='Upload a media file')
    @admin_required
    def post(self):
        if 'file' not in request.files:
            api.abort(400, "No file part")
        file = request.files['file']
        if file.filename == '':
            api.abort(400, "No selected file")
        if file:
            filename = secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(MEDIA_FOLDER, unique_filename)
            try:
                file.save(filepath)
                file_type = 'application/octet-stream'
                if file_extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']:
                    file_type = 'image'
                elif file_extension in ['mp4', 'webm', 'ogg']:
                    file_type = 'video'
                elif file_extension in ['mp3', 'wav', 'aac']:
                    file_type = 'audio'
                elif file_extension in ['pdf']:
                    file_type = 'application/pdf'
                elif file_extension in ['doc', 'docx']:
                    file_type = 'application/msword'
                elif file_extension in ['xls', 'xlsx']:
                    file_type = 'application/vnd.ms-excel'
                elif file_extension in ['txt']:
                    file_type = 'text/plain'

                db_session = SessionLocal()
                try:
                    media = MediaFile(filename=unique_filename, filepath=filepath, file_type=file_type)
                    db_session.add(media)
                    db_session.commit()
                    logging.info(f"Admin uploaded media file: {unique_filename} ({file_type})")
                    return {"message": "Media file uploaded successfully", "filename": unique_filename, "file_type": file_type}, 201
                except Exception as e:
                    db_session.rollback()
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    logging.error(f"Error uploading media file: {e}")
                    api.abort(500, str(e))
                finally:
                    db_session.close()
            except Exception as e:
                if os.path.exists(filepath):
                    os.remove(filepath)
                logging.error(f"Error saving media file: {e}")
                api.abort(500, str(e))
        api.abort(500, "File upload failed")

@ns.route('/admin/media/<int:media_id>')
class AdminMediaFile(Resource):
    @api.doc(description='Delete a media file')
    @admin_required
    def delete(self, media_id):
        db_session = SessionLocal()
        try:
            media = db_session.query(MediaFile).filter(MediaFile.id == media_id).first()
            if not media:
                api.abort(404, "Media file not found")
            filepath = media.filepath
            if os.path.exists(filepath):
                os.remove(filepath)
                logging.info(f"Deleted media file from disk: {filepath}")
            db_session.delete(media)
            db_session.commit()
            logging.info(f"Admin deleted media file from DB: {media_id}")
            return {"message": "Media file deleted successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error deleting media file {media_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/languages')
class Languages(Resource):
    @api.doc(description='Get all languages')
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            languages = db_session.query(Language).order_by(Language.display_name.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Language).count()
            return {
                "languages": [{"id": l.id, "lang_code": l.lang_code, "display_name": l.display_name} for l in languages],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/translations')
class Translations(Resource):
    @api.doc(description='Get all translations from JSON file')
    def get(self):
        return load_translations_from_file()

@ns.route('/translations/<string:lang_code>')
class TranslationsLang(Resource):
    @api.doc(description='Get translations for a specific language')
    def get(self, lang_code):
        translations = load_translations_from_file()
        return translations.get(lang_code, {})

@ns.route('/admin/languages')
class AdminLanguages(Resource):
    @api.expect(language_model)
    @api.doc(description='Add a new language')
    @admin_required
    def post(self):
        data = request.get_json()
        lang_code = data.get('lang_code')
        display_name = data.get('display_name')
        if not lang_code or not display_name:
            api.abort(400, "Language code and display name are required")
        db_session = SessionLocal()
        try:
            language = Language(lang_code=lang_code, display_name=display_name)
            db_session.add(language)
            db_session.commit()
            logging.info(f"Admin added language: {display_name} ({lang_code})")
            return {"message": "Language added successfully"}, 201
        except Exception as e:
            db_session.rollback()
            if "unique constraint" in str(e).lower():
                api.abort(409, "Language with this code already exists")
            logging.error(f"Error adding language: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/languages/<int:language_id>')
class AdminLanguage(Resource):
    @api.expect(language_model)
    @api.doc(description='Update a language')
    @admin_required
    def put(self, language_id):
        data = request.get_json()
        display_name = data.get('display_name')
        if not display_name:
            api.abort(400, "Display name is required")
        db_session = SessionLocal()
        try:
            language = db_session.query(Language).filter(Language.id == language_id).first()
            if not language:
                api.abort(404, "Language not found")
            language.display_name = display_name
            db_session.commit()
            logging.info(f"Admin updated language {language_id} to: {display_name}")
            return {"message": "Language updated successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error updating language {language_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

    @api.doc(description='Delete a language')
    @admin_required
    def delete(self, language_id):
        db_session = SessionLocal()
        try:
            language = db_session.query(Language).filter(Language.id == language_id).first()
            if not language:
                api.abort(404, "Language not found")
            db_session.delete(language)
            db_session.commit()
            logging.info(f"Admin deleted language: {language_id}")
            return {"message": "Language deleted successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error deleting language {language_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/webhooks')
class AdminWebhooks(Resource):
    @api.doc(description='Get all webhooks for admin')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            webhooks = db_session.query(Webhook).order_by(Webhook.event_type.asc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(Webhook).count()
            return {
                "webhooks": [{"id": w.id, "event_type": w.event_type, "url": w.url} for w in webhooks],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

    @api.expect(webhook_model)
    @api.doc(description='Add a new webhook')
    @admin_required
    def post(self):
        data = request.get_json()
        event_type = data.get('event_type')
        url = data.get('url')
        if not event_type or not url:
            api.abort(400, "Event type and URL are required")
        db_session = SessionLocal()
        try:
            webhook = Webhook(event_type=event_type, url=url)
            db_session.add(webhook)
            db_session.commit()
            logging.info(f"Admin added webhook for event: {event_type}")
            return {"message": "Webhook added successfully"}, 201
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error adding webhook: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/webhooks/<int:webhook_id>')
class AdminWebhook(Resource):
    @api.expect(webhook_model)
    @api.doc(description='Update a webhook')
    @admin_required
    def put(self, webhook_id):
        data = request.get_json()
        event_type = data.get('event_type')
        url = data.get('url')
        if not event_type or not url:
            api.abort(400, "Event type and URL are required")
        db_session = SessionLocal()
        try:
            webhook = db_session.query(Webhook).filter(Webhook.id == webhook_id).first()
            if not webhook:
                api.abort(404, "Webhook not found")
            webhook.event_type = event_type
            webhook.url = url
            db_session.commit()
            logging.info(f"Admin updated webhook {webhook_id}")
            return {"message": "Webhook updated successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error updating webhook {webhook_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

    @api.doc(description='Delete a webhook')
    @admin_required
    def delete(self, webhook_id):
        db_session = SessionLocal()
        try:
            webhook = db_session.query(Webhook).filter(Webhook.id == webhook_id).first()
            if not webhook:
                api.abort(404, "Webhook not found")
            db_session.delete(webhook)
            db_session.commit()
            logging.info(f"Admin deleted webhook: {webhook_id}")
            return {"message": "Webhook deleted successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error deleting webhook {webhook_id}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/admin/statistics/daily')
class AdminDailyStatistics(Resource):
    @api.doc(description='Get daily statistics')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        db_session = SessionLocal()
        try:
            stats = db_session.query(DailyStatistics).order_by(DailyStatistics.date.desc()).offset((page-1)*per_page).limit(per_page).all()
            total = db_session.query(DailyStatistics).count()
            return {
                "statistics": [{
                    "id": s.id,
                    "date": s.date,
                    "total_tickets": s.total_tickets,
                    "finished_tickets": s.finished_tickets,
                    "cancelled_tickets": s.cancelled_tickets,
                    "redirected_tickets": s.redirected_tickets,
                    "avg_wait_time": s.avg_wait_time,
                    "avg_service_time": s.avg_service_time
                } for s in stats],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/admin/statistics/operators')
class AdminOperatorStatistics(Resource):
    @api.doc(description='Get operator statistics')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        date_filter = request.args.get('date')
        db_session = SessionLocal()
        try:
            query = db_session.query(OperatorStatistics, Operator.name.label('operator_name')).\
                join(Operator, OperatorStatistics.operator_id == Operator.id)
            if date_filter:
                query = query.filter(OperatorStatistics.date == date_filter)
            stats = query.order_by(OperatorStatistics.date.desc()).offset((page-1)*per_page).limit(per_page).all()
            total = query.count()
            return {
                "statistics": [{
                    "id": s.OperatorStatistics.id,
                    "operator_id": s.OperatorStatistics.operator_id,
                    "operator_name": s.operator_name,
                    "date": s.OperatorStatistics.date,
                    "called_tickets": s.OperatorStatistics.called_tickets,
                    "finished_tickets": s.OperatorStatistics.finished_tickets,
                    "cancelled_tickets": s.OperatorStatistics.cancelled_tickets,
                    "redirected_tickets": s.OperatorStatistics.redirected_tickets,
                    "avg_wait_time": s.OperatorStatistics.avg_wait_time,
                    "avg_service_time": s.OperatorStatistics.avg_service_time
                } for s in stats],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/admin/statistics/services')
class AdminServiceStatistics(Resource):
    @api.doc(description='Get service statistics')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        date_filter = request.args.get('date')
        db_session = SessionLocal()
        try:
            query = db_session.query(ServiceStatistics, Service.name.label('service_name')).\
                join(Service, ServiceStatistics.service_id == Service.id)
            if date_filter:
                query = query.filter(ServiceStatistics.date == date_filter)
            stats = query.order_by(ServiceStatistics.date.desc()).offset((page-1)*per_page).limit(per_page).all()
            total = query.count()
            return {
                "statistics": [{
                    "id": s.ServiceStatistics.id,
                    "service_id": s.ServiceStatistics.service_id,
                    "service_name": s.service_name,
                    "date": s.ServiceStatistics.date,
                    "called_tickets": s.ServiceStatistics.called_tickets,
                    "finished_tickets": s.ServiceStatistics.finished_tickets,
                    "cancelled_tickets": s.ServiceStatistics.cancelled_tickets,
                    "redirected_tickets": s.ServiceStatistics.redirected_tickets,
                    "avg_wait_time": s.ServiceStatistics.avg_wait_time,
                    "avg_service_time": s.ServiceStatistics.avg_service_time
                } for s in stats],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/admin/statistics/export')
class AdminStatisticsExport(Resource):
    @api.doc(description='Export statistics as Excel')
    @admin_required
    def get(self):
        stat_type = request.args.get('type', 'daily')
        date_filter = request.args.get('date')
        db_session = SessionLocal()
        try:
            if stat_type == 'daily':
                query = db_session.query(DailyStatistics)
                if date_filter:
                    query = query.filter(DailyStatistics.date == date_filter)
                stats = query.order_by(DailyStatistics.date.desc()).all()
                data = [{
                    'Date': s.date,
                    'Total Tickets': s.total_tickets,
                    'Finished Tickets': s.finished_tickets,
                    'Cancelled Tickets': s.cancelled_tickets,
                    'Redirected Tickets': s.redirected_tickets,
                    'Avg Wait Time (s)': s.avg_wait_time,
                    'Avg Service Time (s)': s.avg_service_time
                } for s in stats]
                filename = f"daily_statistics_{get_current_tashkent_time().strftime('%Y%m%d_%H%M%S')}.xlsx"
            elif stat_type == 'operators':
                query = db_session.query(OperatorStatistics, Operator.name.label('operator_name')).\
                    join(Operator, OperatorStatistics.operator_id == Operator.id)
                if date_filter:
                    query = query.filter(OperatorStatistics.date == date_filter)
                stats = query.order_by(OperatorStatistics.date.desc()).all()
                data = [{
                    'Date': s.OperatorStatistics.date,
                    'Operator': s.operator_name,
                    'Called Tickets': s.OperatorStatistics.called_tickets,
                    'Finished Tickets': s.OperatorStatistics.finished_tickets,
                    'Cancelled Tickets': s.OperatorStatistics.cancelled_tickets,
                    'Redirected Tickets': s.OperatorStatistics.redirected_tickets,
                    'Avg Wait Time (s)': s.OperatorStatistics.avg_wait_time,
                    'Avg Service Time (s)': s.OperatorStatistics.avg_service_time
                } for s in stats]
                filename = f"operator_statistics_{get_current_tashkent_time().strftime('%Y%m%d_%H%M%S')}.xlsx"
            elif stat_type == 'services':
                query = db_session.query(ServiceStatistics, Service.name.label('service_name')).\
                    join(Service, ServiceStatistics.service_id == Service.id)
                if date_filter:
                    query = query.filter(ServiceStatistics.date == date_filter)
                stats = query.order_by(ServiceStatistics.date.desc()).all()
                data = [{
                    'Date': s.ServiceStatistics.date,
                    'Service': s.service_name,
                    'Called Tickets': s.ServiceStatistics.called_tickets,
                    'Finished Tickets': s.ServiceStatistics.finished_tickets,
                    'Cancelled Tickets': s.ServiceStatistics.cancelled_tickets,
                    'Redirected Tickets': s.ServiceStatistics.redirected_tickets,
                    'Avg Wait Time (s)': s.ServiceStatistics.avg_wait_time,
                    'Avg Service Time (s)': s.ServiceStatistics.avg_service_time
                } for s in stats]
                filename = f"service_statistics_{get_current_tashkent_time().strftime('%Y%m%d_%H%M%S')}.xlsx"
            else:
                api.abort(400, "Invalid statistics type")

            df = pd.DataFrame(data)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df.to_excel(writer, index=False, sheet_name='Statistics')
            output.seek(0)
            logging.info(f"Exported {filename} with {len(data)} records")
            return send_file(
                output,
                as_attachment=True,
                download_name=filename,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
        except Exception as e:
            logging.error(f"Error exporting statistics: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

@ns.route('/ticket/<string:ticket_number>/status')
class TicketStatus(Resource):
    @api.doc(description='Get status of a ticket')  # исправлено
    def get(self, ticket_number):
        db_session = SessionLocal()
        try:
            ticket = db_session.query(Ticket, Service.name.label('service_name'), Operator.name.label('operator_name')).\
                join(Service, Ticket.service_id == Service.id).\
                outerjoin(Operator, Ticket.operator_id == Operator.id).\
                filter(Ticket.number == ticket_number).first()
            if not ticket:
                api.abort(404, "Ticket not found")
            queue_position = db_session.query(Ticket).\
                Ticket_status(Ticket.status == 'waiting', Ticket.service_id == ticket.Ticket.service_id).\
                filter(Ticket.created_at <= ticket.Ticket.created_at).count()
            return {
                "ticket_number": ticket.Ticket.number,
                "status": ticket.Ticket.status,
                "service_name": ticket.service_name,
                "operator_name": ticket.operator_name,
                "created_at": ticket.Ticket.created_at.isoformat(),
                "called_at": ticket.Ticket.called_at.isoformat() if ticket.Ticket.called_at else None,
                "finished_at": ticket.Ticket.finished_at.isoformat() if ticket.Ticket.finished_at else None,
                "queue_position": queue_position if ticket.Ticket.status == 'waiting' else None
            }
        finally:
            db_session.close()

@ns.route('/admin/tickets')
class AdminTickets(Resource):
    @api.doc(description='Get all tickets for admin')
    @admin_required
    def get(self):
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        status = request.args.get('status')
        db_session = SessionLocal()
        try:
            query = db_session.query(Ticket, Service.name.label('service_name'), Operator.name.label('operator_name')).\
                join(Service, Ticket.service_id == Service.id).\
                outerjoin(Operator, Ticket.operator_id == Operator.id)
            if status:
                query = query.filter(Ticket.status == status)
            tickets = query.order_by(Ticket.created_at.desc()).offset((page-1)*per_page).limit(per_page).all()
            total = query.count()
            return {
                "tickets": [{
                    "id": t.Ticket.id,
                    "number": t.Ticket.number,
                    "status": t.Ticket.status,
                    "service_name": t.service_name,
                    "operator_name": t.operator_name,
                    "created_at": t.Ticket.created_at.isoformat(),
                    "called_at": t.Ticket.called_at.isoformat() if t.Ticket.called_at else None,
                    "finished_at": t.Ticket.finished_at.isoformat() if t.Ticket.finished_at else None,
                    "priority": t.Ticket.priority
                } for t in tickets],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        finally:
            db_session.close()

@ns.route('/admin/tickets/<string:ticket_number>')
class AdminTicket(Resource):
    @api.doc(description='Update ticket priority or status')
    @admin_required
    def put(self, ticket_number):
        data = request.get_json()
        priority = data.get('priority')
        status = data.get('status')
        if priority is None and status is None:
            api.abort(400, "Priority or status must be provided")
        db_session = SessionLocal()
        try:
            ticket = db_session.query(Ticket).filter(Ticket.number == ticket_number).first()
            if not ticket:
                api.abort(404, "Ticket not found")
            if priority is not None:
                ticket.priority = priority
            if status:
                ticket.status = status
                if status == 'called' and not ticket.called_at:
                    ticket.called_at = get_current_tashkent_time()
                elif status == 'finished' and not ticket.finished_at:
                    ticket.finished_at = get_current_tashkent_time()
            db_session.commit()
            logging.info(f"Admin updated ticket {ticket_number}: priority={priority}, status={status}")
            socketio.emit('update_queue', {'ticket': ticket_number, 'operator_id': ticket.operator_id or 'N/A'})
            return {"message": "Ticket updated successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error updating ticket {ticket_number}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

    @api.doc(description='Delete a ticket')
    @admin_required
    def delete(self, ticket_number):
        db_session = SessionLocal()
        try:
            ticket = db_session.query(Ticket).filter(Ticket.number == ticket_number).first()
            if not ticket:
                api.abort(404, "Ticket not found")
            db_session.delete(ticket)
            db_session.commit()
            logging.info(f"Admin deleted ticket: {ticket_number}")
            socketio.emit('remove_ticket', {'ticket': ticket_number, 'operator_id': ticket.operator_id or 'N/A'})
            return {"message": "Ticket deleted successfully"}, 200
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error deleting ticket {ticket_number}: {e}")
            api.abort(500, str(e))
        finally:
            db_session.close()

# --- Socket.IO Events ---

@socketio.on('connect')
def handle_connect():
    logging.info("Client connected to Socket.IO")

@socketio.on('disconnect')
def handle_disconnect():
    logging.info("Client disconnected from Socket.IO")

@socketio.on('join_chat')
def handle_join_chat(data):
    ticket_number = data.get('ticket_number')
    sender_type = data.get('sender_type')
    sender_id = data.get('sender_id')
    if not ticket_number or not sender_type or not sender_id:
        emit('error', {'message': 'Missing required fields'})
        return
    join_room(ticket_number)
    logging.info(f"{sender_type} {sender_id} joined chat for ticket {ticket_number}")

@socketio.on('send_message')
def handle_send_message(data):
    ticket_number = data.get('ticket_number')
    sender_type = data.get('sender_type')
    sender_id = data.get('sender_id')
    content = data.get('content')
    file_url = data.get('file_url')
    file_type = data.get('file_type')

    if not ticket_number or not sender_type or not sender_id or (not content and not file_url):
        emit('error', {'message': 'Missing required fields'})
        return

    db_session = SessionLocal()
    try:
        ticket = db_session.query(Ticket).filter(Ticket.number == ticket_number).first()
        if not ticket:
            emit('error', {'message': 'Ticket not found'})
            return
        message = ChatMessage(
            ticket_number=ticket_number,
            sender_type=sender_type,
            sender_id=sender_id,
            content=content,
            file_url=file_url,
            file_type=file_type,
            created_at=get_current_tashkent_time()
        )
        db_session.add(message)
        db_session.commit()
        logging.info(f"Message sent in chat for ticket {ticket_number} by {sender_type} {sender_id}")

        message_data = {
            'ticket_number': ticket_number,
            'sender_type': sender_type,
            'sender_id': sender_id,
            'content': content,
            'file_url': file_url,
            'file_type': file_type,
            'created_at': message.created_at.isoformat()
        }
        emit('new_message', message_data, room=ticket_number)

        if sender_type == 'client' and ticket.operator_id:
            operator = db_session.query(Operator).filter(Operator.id == ticket.operator_id).first()
            if operator and operator.telegram_chat_id:
                notification = (
                    f"Yangi xabar: <b>{ticket_number}</b> talonidan.\n"
                    f"{content or 'Fayl yuborildi'}"
                )
                send_telegram_message_async.delay(operator.telegram_chat_id, notification)
        elif sender_type == 'operator' and ticket.client_telegram_chat_id:
            notification = (
                f"Operator xabari: <b>{ticket_number}</b> talonida.\n"
                f"{content or 'Fayl yuborildi'}"
            )
            send_telegram_message_async.delay(ticket.client_telegram_chat_id, notification)
    except Exception as e:
        db_session.rollback()
        logging.error(f"Error sending message for ticket {ticket_number}: {e}")
        emit('error', {'message': str(e)})
    finally:
        db_session.close()

# --- Run Application ---

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
