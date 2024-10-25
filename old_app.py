import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import requests
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import xml.etree.ElementTree as ET

load_dotenv()

# Initialize app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
#app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

#db = SQLAlchemy(app)

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Stripe API key
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# QuickBooks API settings
client_id = os.getenv('QB_CLIENT_ID')
client_secret = os.getenv('QB_CLIENT_SECRET')
redirect_uri = os.getenv('QB_REDIRECT_URI')
authorization_base_url = 'https://appcenter.intuit.com/connect/oauth2'
token_url = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer'
quickbooks_api_url = 'https://sandbox-quickbooks.api.intuit.com/v3/company'

# Setup logging
def setup_logging(app):
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/handles_project.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Handles Project startup')

setup_logging(app)

# Models
#class User(db.Model, UserMixin):
#   id = db.Column(db.Integer, primary_key=True)
#    username = db.Column(db.String(80), unique=True, nullable=False)
#   email = db.Column(db.String(120), unique=True, nullable=False)
#   password_hash = db.Column(db.String(128))
#   company_name = db.Column(db.String(120))
#   quickbooks_token = db.Column(db.String(500))

#class Tactic(db.Model):
#    __tablename__ = 'tactics'
#    id = db.Column(db.Integer, primary_key=True)
#    name = db.Column(db.String(80))

def get_tactics():
    # return Tactic.query.all()  # Original code (commented out)
    return []  # Temporary placeholder

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# OAuth QuickBooks session
def create_quickbooks_session():
    return OAuth2Session(client_id, token=session.get('quickbooks_token'), redirect_uri=redirect_uri)

# Function to get all tactics from the database
def get_tactics():
    return Tactic.query.all()

# Routes

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login logic here
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = True if request.form.get('remember_me') else False

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember_me)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Register Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get the form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the user already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('signup'))

        # Hash the password and create a new user
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password)

        # Add the new user to the database
        #db.session.add(new_user)
        #db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/')
def home():
    tactics = get_tactics()
    return render_template('index.html', tactics=tactics)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/connect_quickbooks')
@login_required
def connect_quickbooks():
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=['com.intuit.quickbooks.accounting'])
    authorization_url, state = oauth.authorization_url(authorization_base_url)
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, state=session['oauth_state'])
    token = oauth.fetch_token(token_url, authorization_response=request.url, client_secret=client_secret)
    session['quickbooks_token'] = token
    flash("Successfully connected to QuickBooks", "success")
    return redirect(url_for('dashboard'))

@app.route('/sales_analysis')
def sales_analysis():
    if 'oauth_token' not in session or 'realm_id' not in session:
        return redirect(url_for('connect_quickbooks'))
    return render_template('sales_analysis.html')

@app.route('/api/sales_analysis_data')
def sales_analysis_data():
    app.logger.info(f"Received request with params: {request.args}")

    start_date = request.args.get('start_date', '2014-01-01')
    end_date = request.args.get('end_date', '2017-12-31')
    duration = request.args.get('duration', 'month')

    app.logger.info(f"Using duration: {duration}")

    if 'oauth_token' not in session or 'realm_id' not in session:
        app.logger.error("OAuth token or realm_id not found in session")
        return jsonify({"error": "Not authenticated"}), 401

    quickbooks = create_quickbooks_session()
    realm_id = session['realm_id']

    try:
        invoice_url = f"{quickbooks_api_url}/{realm_id}/query"
        invoice_params = {'query': f"SELECT * FROM Invoice WHERE TxnDate >= '{start_date}' AND TxnDate <= '{end_date}'"}
        invoice_response = quickbooks.get(invoice_url, params=invoice_params)
        app.logger.info(f"Raw invoice response: {invoice_response.text}")
        invoice_response.raise_for_status()
        root = ET.fromstring(invoice_response.text)
        namespace = {'ns': 'http://schema.intuit.com/finance/v3'}
        app.logger.info(f"XML root tag: {root.tag}")
        app.logger.info(f"Number of Invoice elements: {len(root.findall('.//ns:Invoice', namespace))}")
        invoices_data = []
        for invoice in root.findall('.//ns:Invoice', namespace):
            invoice_data = {
                'Id': invoice.find('ns:Id', namespace).text,
                'DocNumber': invoice.find('ns:DocNumber', namespace).text,
                'TxnDate': invoice.find('ns:TxnDate', namespace).text,
                'TotalAmt': invoice.find('ns:TotalAmt', namespace).text,
                'CustomerRef': invoice.find('ns:CustomerRef', namespace).attrib.get('name', 'Unknown')
            }
            invoices_data.append(invoice_data)

        monthly_data, invoices = process_sales_data(invoices_data, duration)
        data = {"monthly_data": monthly_data, "invoices": invoices}
        app.logger.info(f"Sending data: {data}")
        return jsonify(data)

    except requests.exceptions.RequestException as req_error:
        app.logger.error(f"Request to QuickBooks API failed: {str(req_error)}")
        return jsonify({"error": "Failed to fetch data from QuickBooks API"}), 500
    except ET.ParseError as xml_error:
        app.logger.error(f"Failed to parse XML response: {str(xml_error)}")
        return jsonify({"error": "Failed to parse response from QuickBooks API"}), 500
    except Exception as e:
        app.logger.error(f"An error occurred: {str(e)}")
        return jsonify({"error": "An error occurred while processing data from QuickBooks."}), 500

def process_sales_data(invoices_data, duration):
    monthly_data = []
    invoices = []

    for invoice in invoices_data:
        date = invoice['TxnDate']
        amount = float(invoice['TotalAmt'])
        customer_name = invoice['CustomerRef']
        invoices.append({"date": date, "invoice_number": invoice['DocNumber'], "customer_name": customer_name, "amount": amount})
        if duration == 'day':
            period = date
        elif duration == 'month':
            period = date[:7]
        elif duration == 'quarter':
            year = date[:4]
            month = int(date[5:7])
            quarter = (month - 1) // 3 + 1
            period = f"{year}-Q{quarter}"
        elif duration == 'year':
            period = date[:4]
        else:
            period = date[:7]

        period_data = next((item for item in monthly_data if item["Period"] == period), None)
        if period_data is None:
            period_data = {"Period": period, "activeClients": set(), "avgSalesValue": 0, "transactions": 0, "revenue": 0}
            monthly_data.append(period_data)

        period_data["activeClients"].add(customer_name)
        period_data["transactions"] += 1
        period_data["revenue"] += amount

    for period_data in monthly_data:
        if period_data["transactions"] > 0:
            period_data["avgSalesValue"] = period_data["revenue"] / period_data["transactions"]
        period_data["activeClients"] = len(period_data["activeClients"])

    return monthly_data, invoices

@app.route('/marketing_plan')
def marketing_plan():
    tactics = get_tactics()  # Fetch tactics from the database
    return render_template('marketing_plan.html', tactics=tactics)

@app.route('/get_tactic_impact', methods=['POST'])
def get_tactic_impact():
    tactic_id = request.json.get('tactic_id')
    # Implement logic to fetch tactic impact data from your database
    impact = {
        'users': 1120,
        'AC': 0.15,
        'ASV': -0.08,
        'NT': 0.0
    }
    return jsonify(success=True, impact=impact)

@app.route('/sweet_spot_analysis')
def sweet_spot_analysis():
    return render_template('sweet_spot_analysis.html')

@app.route('/resource_center')
def resource_center():
    return render_template('resource_center.html')

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/user_profile')
def user_profile():
    return render_template('user_profile.html')

@app.route('/help_support')
def help_support():
    return render_template('help_support.html')

@app.route('/community')
def community():
    return render_template('community.html')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(400)
def bad_request_error(error):
    app.logger.error(f"400 error occurred: {error}")
    return render_template('400.html'), 400

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 error occurred: {error}")
    db.session.rollback()
    return render_template('500.html'), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Add this temporarily to create the database tables
with app.app_context():
    db.create_all()

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('dashboard.html')

