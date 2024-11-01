import os
import logging
#from flask_migrate import Migrate
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import requests
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import xml.etree.ElementTree as ET

load_dotenv()

# Initialize app
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
#app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

#db = SQLAlchemy(app)

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    pass

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

# Placeholder for get_tactics without DB
def get_tactics():
    return []  # Temporary placeholder

# User Loader
@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        user = User()
        user.id = user_id
        return user
    return None  # Placeholder until the database is back in use

# OAuth QuickBooks session
def create_quickbooks_session():
    return OAuth2Session(client_id, token=session.get('quickbooks_token'), redirect_uri=redirect_uri)

# Routes
@login_manager.user_loader
def load_user(user_id):
    # Replace this with actual user loading logic
    if user_id is not None:
        user = User()
        user.id = user_id
        return user
    return None

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = True if request.form.get('remember_me') else False

        # Dummy user validation (placeholder)
        if username == 'admin' and password == 'password':
            login_user(username, remember=remember_me)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Register Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        flash('Account creation is disabled for now.', 'danger')
        return redirect(url_for('signup'))

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

@app.route('/marketing_plan')
@login_required  # if this needs to be protected
def marketing_plan():
    return render_template('marketing_plan.html')

@app.route('/sweet_spot_analysis')
@login_required
def sweet_spot_analysis():
    return render_template('sweet_spot_analysis.html')

@app.route('/sales_analysis')
def sales_analysis():
    if 'quickbooks_token' not in session or 'realm_id' not in session:
        return redirect(url_for('connect_quickbooks'))
    
    qbo = create_quickbooks_session()
    realm_id = session['realm_id']
    query_url = f"{quickbooks_api_url}/{realm_id}/query?query=SELECT * FROM Invoice"
    
    try:
        response = qbo.get(query_url, headers={"Accept": "application/json"})
        response.raise_for_status()  # Raise an error if the request failed
        data = response.json()
        return render_template('sales_analysis.html', data=data)
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching QBO data: {e}")
        flash("Error retrieving data from QuickBooks", "danger")
        return redirect(url_for('dashboard'))

@app.route('/resource_center')
@login_required
def resource_center():
    return render_template('resource_center.html')

@app.route('/blog')
def blog():  # Note: No @login_required since blogs are usually public
    return render_template('blog.html')

@app.route('/user_profile')
@login_required
def user_profile():
    return render_template('user_profile.html')

@app.route('/help_support')
def help_support():  # No login_required as help should be accessible to everyone
    return render_template('help_support.html')

@app.route('/community')
def community():
    return render_template('community.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()  # This comes from flask_login
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 error occurred: {error}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
