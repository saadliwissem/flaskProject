from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import re
import logging
import secrets  # For generating tokens

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Secret key for session management
app.secret_key = 'your_secret_key'

# Load environment variables from the .env file
load_dotenv()

# Retrieve the database credentials from environment variables
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST')
db_name = os.getenv('DB_NAME')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{db_user}:{db_password}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

# Protect routes using a decorator
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'token' not in session:
            # If no token is found in the session, redirect to login
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# Main route to display the home page (protected route)
# Sample jewelry items, replace this with your database query
class JewelryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255), nullable=False)

@app.route('/')
@login_required
def home():
    search_query = request.args.get('Search', '')
    if search_query:
        # Fetch jewelry items that match the search query
        jewelry_items = JewelryItem.query.filter(
            (JewelryItem.title.ilike(f'%{search_query}%')) |
            (JewelryItem.description.ilike(f'%{search_query}%'))
        ).all()
    else:
        # Fetch all jewelry items if no search query
        jewelry_items = JewelryItem.query.all()
    
    return render_template('index.html', jewelry_items=jewelry_items)
# Route to display the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    messages = []
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        logger.debug(f"Login attempt for username: {username}")

        # Fetch user from the database
        user = User.query.filter((User.username == username) | (User.email == username)).first()

        if user and check_password_hash(user.password, password):
            logger.debug(f"User found and password correct for: {user.username}")

            # Generate a token and store it in the session
            session['token'] = secrets.token_hex(16)  # Generating a random token
            session['username'] = user.username  # Store username in session for display purposes
            logger.info(f"User '{username}' logged in successfully with token: {session['token']}")
            
            # Redirect to the home page after successful login
            return redirect(url_for('home'))

        else:
            logger.warning(f"Login failed for user '{username}'. Invalid username or password.")
            messages.append('Invalid username or password. Please try again.')

    return render_template('login.html', messages=messages)

# Email regex for validation
email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

@app.route('/signup', methods=['POST'])
def signup():
    messages = []
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # Validate email format
    if not re.match(email_regex, email):
        messages.append('Invalid email format.')
        return render_template('signup.html', messages=messages)

    # Validate that passwords match
    if password != confirm_password:
        messages.append('Passwords do not match.')
        return render_template('signup.html', messages=messages)

    # Check for existing user
    existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
    if existing_user:
        messages.append('Username or email already exists.')
        logger.warning('Username or email already exists.')
        return render_template('signup.html', messages=messages)

    # Create new user
    new_user = User(username=username, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    messages.append('Signup successful! You can now login.')
    return render_template('login.html', messages=messages)

# Display signup page
@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

# Route to handle logging out
@app.route('/logout')
def logout():
    session.clear()  # Clear the session data (logout the user)
    logger.info('User logged out and session cleared.')
    return redirect(url_for('login'))


# handle shopping card 
@app.route('/add_to_basket/<int:item_id>', methods=['POST'])
@login_required
def add_to_basket(item_id):
    quantity = int(request.form.get('quantity', 1))
    
    # Fetch the item from the database
    item = JewelryItem.query.get(item_id)
    
    if not item:
        return redirect(url_for('home'))  # Item doesn't exist

    # Initialize basket in session if it doesn't exist
    if 'basket' not in session:
        session['basket'] = {}

    # If the item is already in the basket, update the quantity
    if str(item_id) in session['basket']:
        session['basket'][str(item_id)]['quantity'] += quantity
    else:
        session['basket'][str(item_id)] = {
            'title': item.title,
            'price': item.price,
            'quantity': quantity,
            'image': item.image
        }

    session.modified = True  # To notify Flask that the session has been modified
    return redirect(url_for('view_basket'))

# Route to view the basket
@app.route('/basket')
@login_required
def view_basket():
    basket = session.get('basket', {})
    total_price = sum(item['price'] * item['quantity'] for item in basket.values())
    return render_template('basket.html', basket=basket, total_price=total_price)

# Route to update item quantity in the basket
@app.route('/update_basket/<int:item_id>', methods=['POST'])
@login_required
def update_basket(item_id):
    quantity = int(request.form.get('quantity', 1))
    
    if 'basket' in session and str(item_id) in session['basket']:
        if quantity <= 0:
            # If quantity is 0 or less, remove the item from the basket
            session['basket'].pop(str(item_id), None)
        else:
            # Otherwise, update the item quantity
            session['basket'][str(item_id)]['quantity'] = quantity
    
    session.modified = True
    return redirect(url_for('view_basket'))

# Route to remove an item from the basket
@app.route('/remove_from_basket/<int:item_id>', methods=['POST'])
@login_required
def remove_from_basket(item_id):
    if 'basket' in session and str(item_id) in session['basket']:
        session['basket'].pop(str(item_id), None)
        session.modified = True
    return redirect(url_for('view_basket'))

# Route to proceed to purchase
@app.route('/purchase', methods=['POST'])
@login_required
def purchase():
    basket = session.get('basket', {})
    if not basket:
        return redirect(url_for('view_basket'))

    # Handle the purchase process (e.g., saving the order to the database)

    # Clear the basket after purchase
    session.pop('basket', None)
    session.modified = True

    # Return a purchase confirmation
    return render_template('purchase_confirmation.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)