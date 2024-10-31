from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import pandas as pd
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
import pyotp
import os
import logging
import ssl
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://your_rds_user:your_rds_password@your_rds_endpoint:5432/your_database_name'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')
app.config['ENCRYPTION_KEY'] = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())  # Securely store and manage this key
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Twilio client
twilio_client = Client('YOUR_TWILIO_ACCOUNT_SID', 'YOUR_TWILIO_AUTH_TOKEN')

# Set up encryption
fernet = Fernet(app.config['ENCRYPTION_KEY'])

# Set up logging for audit logs
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False, default=pyotp.random_base32())
    column_mapping = db.Column(db.JSON, nullable=True)
    messages = db.relationship('Message', back_populates='user')

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.LargeBinary)  # Encrypted
    phone_number = db.Column(db.LargeBinary)  # Encrypted
    custom_fields = db.Column(db.LargeBinary)  # Encrypted
    user = db.relationship('User', back_populates='contacts')

User.contacts = db.relationship('Contact', back_populates='user')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    from_number = db.Column(db.String(20), nullable=False)
    body = db.Column(db.LargeBinary, nullable=False)  # Encrypted
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user = db.relationship('User', back_populates='messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def encrypt_data(data):
    return fernet.encrypt(data.encode())

def decrypt_data(data):
    return fernet.decrypt(data).decode()

@app.route('/')
def home():
    return render_template('home.html', title="Home")

@app.route('/pricing')
def pricing():
    return render_template('pricing.html', title="Pricing")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']
        hashed_password = generate_password_hash(password, method='sha256')
        otp_secret = pyotp.random_base32()

        new_user = User(email=email, password=hashed_password, phone_number=phone_number, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', title="Register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['pre_2fa_user_id'] = user.id
            totp = pyotp.TOTP(user.otp_secret)
            otp = totp.now()
            twilio_client.messages.create(
                body=f'Your verification code is {otp}',
                from_='YOUR_TWILIO_NUMBER',
                to=user.phone_number
            )
            logging.info(f'2FA OTP sent to user: {user.id}')
            return redirect(url_for('verify_otp'))

        logging.warning(f'Failed login attempt for user: {email}')
        return "Invalid credentials", 401

    return render_template('login.html', title="Login")

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        user_id = session.get('pre_2fa_user_id')
        if not user_id:
            return jsonify(message="Session expired, please login again"), 403

        user = User.query.get(user_id)
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            logging.info(f'User {user.id} logged in successfully')
            return redirect(url_for('dashboard'))

        logging.warning(f'Invalid OTP attempt for user: {user.id}')
        return "Invalid OTP", 401

    return render_template('verify_otp.html', title="Verify OTP")

@app.route('/logout')
@login_required
def logout():
    logging.info(f'User {current_user.id} logged out')
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title="Dashboard")

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part", 400
        file = request.files['file']
        if file.filename == '':
            return "No selected file", 400

        file_extension = os.path.splitext(file.filename)[1].lower()

        try:
            if file_extension == '.xlsx' or file_extension == '.xls':
                df = pd.read_excel(file)
            elif file_extension == '.csv':
                df = pd.read_csv(file)
            else:
                return "Unsupported file type", 400
        except Exception as e:
            logging.error(f'Error processing file upload: {str(e)}')
            return str(e), 400

        column_mapping = current_user.column_mapping or {}
        contacts_data = []

        for _, row in df.iterrows():
            contact_data = {
                'user_id': current_user.id,
                'custom_fields': {}
            }
            for db_field, file_column in column_mapping.items():
                if db_field == 'name':
                    contact_data['name'] = encrypt_data(row[file_column])
                elif db_field == 'phone_number':
                    contact_data['phone_number'] = encrypt_data(row[file_column])
                else:
                    contact_data['custom_fields'][db_field] = encrypt_data(row[file_column])

            contacts_data.append(Contact(**contact_data))

        db.session.bulk_save_objects(contacts_data)
        db.session.commit()
        logging.info(f'{len(contacts_data)} contacts uploaded by user {current_user.id}')

        return "File uploaded and contacts stored", 200

    return render_template('upload.html', title="Upload Contacts")

@app.route('/send_campaign', methods=['GET', 'POST'])
@login_required
def send_campaign():
    if request.method == 'POST':
        message_template = request.form['message_template']

        contacts = Contact.query.filter_by(user_id=current_user.id).all()

        for contact in contacts:
            custom_fields = json.loads(decrypt_data(contact.custom_fields))
            custom_fields.update({'name': decrypt_data(contact.name), 'phone_number': decrypt_data(contact.phone_number)})
            try:
                message = message_template.format(**custom_fields)
                twilio_client.messages.create(
                    body=message,
                    from_='YOUR_TWILIO_NUMBER',
                    to=decrypt_data(contact.phone_number)
                )
            except KeyError as e:
                logging.error(f'Missing field in template for user {current_user.id}: {e}')
                return f"Missing field in template: {e}", 400

        logging.info(f'Campaign messages sent by user {current_user.id}')
        return "Campaign messages sent", 200

    return render_template('send_campaign.html', title="Send Campaign")

@app.route('/set_mapping', methods=['POST'])
@login_required
def set_mapping():
    mapping = request.json
    current_user.column_mapping = mapping
    db.session.commit()
    logging.info(f'Column mapping set by user {current_user.id}')
    return jsonify(message="Mapping set successfully"), 200

@app.route('/incoming_message', methods=['POST'])
def incoming_message():
    from_number = request.form['From']
    body = request.form['Body']
    user = User.query.filter_by(phone_number=from_number).first()
    
    if user:
        new_message = Message(user_id=user.id, from_number=from_number, body=encrypt_data(body))
        db.session.add(new_message)
        db.session.commit()

        response = MessagingResponse()
        response.message("Thank you for your message. We will get back to you soon.")
        return str(response)
    
    return '', 200

@app.route('/messages')
@login_required
def messages():
    user_messages = Message.query.filter_by(user_id=current_user.id).all()
    return render_template('messages.html', title="Messages", messages=user_messages)

if __name__ == '__main__':
    db.create_all()
    app.run(ssl_context=('path_to_cert.pem', 'path_to_key.pem'), debug=True)
