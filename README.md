HIPAA-Compliant Two-Way Text Messaging Platform

This is a Flask-based web application for creating HIPAA-compliant, two-way SMS campaigns using Twilio. It includes secure user registration, two-factor authentication (2FA), and encrypted data handling for contacts and messages, with options to upload contact lists and send personalized SMS campaigns.

Features
Two-Way Text Messaging: Send and receive SMS messages securely using Twilio API.
User Authentication & 2FA: Secure login with optional two-factor authentication using SMS-based OTP.
Contact Management: Users can upload contact lists in CSV/Excel formats and map custom fields.
Encrypted Data Storage: All sensitive data is encrypted, making it suitable for HIPAA-compliant applications.
Pricing Plans: Display different pricing plans for users.
Technologies
Backend: Python, Flask, Flask-Login, Flask-SQLAlchemy
Frontend: HTML/CSS (Bootstrap)
Database: PostgreSQL
External APIs: Twilio for SMS, pyOTP for 2FA
Encryption: Cryptography package for data encryption
HIPAA Compliance: Secure data transmission with SSL/TLS, encrypted data storage
Setup and Installation
Prerequisites
Python 3.6+
PostgreSQL
Twilio account
Installation Steps
Clone the repository:

bash
git clone https://github.com/yourusername/yourproject.git
cd yourproject
Create a virtual environment:

bash
Copy code
python3 -m venv venv
source venv/bin/activate
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Configure PostgreSQL Database:

Create a new PostgreSQL database and user:

bash
sudo -u postgres psql
CREATE DATABASE your_database_name;
CREATE USER your_rds_user WITH PASSWORD 'your_rds_password';
GRANT ALL PRIVILEGES ON DATABASE your_database_name TO your_rds_user;
Update the database URI in app.py:

python
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://your_rds_user:your_rds_password@localhost/your_database_name'
Set up Twilio:

Sign up for Twilio and get your Account SID, Auth Token, and a Twilio phone number for sending SMS.

Environment Variables:

Set up environment variables for secure keys (e.g., Twilio credentials, encryption keys):

bash
export SECRET_KEY="your_secret_key"
export TWILIO_ACCOUNT_SID="your_twilio_account_sid"
export TWILIO_AUTH_TOKEN="your_twilio_auth_token"
export ENCRYPTION_KEY="your_generated_encryption_key"
Initialize the Database:

bash
flask db init
flask db migrate
flask db upgrade
Run the Application: Ensure SSL/TLS is set up for HIPAA compliance and run the app.

bash
flask run --cert=path_to_cert.pem --key=path_to_key.pem
Project Structure
bash
/project_directory
├── app.py               # Main application file with routes and logic
├── requirements.txt     # Python package dependencies
├── /static              # Static files (CSS)
│   └── /css
│       └── styles.css
├── /templates           # HTML templates
│   ├── base.html
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── send_campaign.html
│   ├── upload.html
│   ├── verify_otp.html
│   └── pricing.html
└── README.md            # Project documentation
Usage
Register/Login: Users can register and log in. After logging in, if 2FA is enabled, they receive an OTP via SMS.
Verify OTP: Users enter the OTP to complete the login process.
Upload Contacts: Users can upload contacts as a CSV or Excel file, mapping columns to fields like name and phone number.
Send Campaign: Users can create a message template and send personalized campaigns to their contacts.
Receive Messages: Messages sent by contacts are stored and viewable in the user dashboard.
Pricing: Users can view available service tiers on the pricing page.
Security and HIPAA Compliance
This application incorporates several measures for HIPAA compliance:

Data Encryption: All sensitive data is encrypted using the cryptography library.
HTTPS: Ensure all connections use HTTPS for secure data transmission.
Audit Logging: User actions and system events are logged for auditing.
Access Control: Two-factor authentication for secure access to sensitive information.
