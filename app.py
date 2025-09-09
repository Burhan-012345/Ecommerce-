import os
import random
import string
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from twilio.rest import Client
import razorpay

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secure random secret key

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ahmedburhan4834@gmail.com'
app.config['MAIL_PASSWORD'] = 'cnzwlrvuqvskella'

# Twilio configuration
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', 'AC28038321de165fdff3636b8fa0cb605b')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '72633e1135c123e0a708199f48e6b3ba')
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER', '+12703987622')

# Razorpay configuration
RAZORPAY_KEY_ID = 'your_razorpay_key_id'  # Replace with your Razorpay key
RAZORPAY_KEY_SECRET = 'your_razorpay_key_secret'  # Replace with your Razorpay secret

# Initialize extensions
mail = Mail(app)
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 email TEXT UNIQUE NOT NULL,
                 phone TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL,
                 email_verified INTEGER DEFAULT 0,
                 phone_verified INTEGER DEFAULT 0,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create products table
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 description TEXT,
                 price REAL NOT NULL,
                 image_url TEXT,
                 category TEXT,
                 stock INTEGER DEFAULT 0,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create cart table
    c.execute('''CREATE TABLE IF NOT EXISTS cart
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 product_id INTEGER NOT NULL,
                 quantity INTEGER DEFAULT 1,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY (user_id) REFERENCES users (id),
                 FOREIGN KEY (product_id) REFERENCES products (id))''')
    
    # Create orders table
    c.execute('''CREATE TABLE IF NOT EXISTS orders
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 total_amount REAL NOT NULL,
                 status TEXT DEFAULT 'pending',
                 razorpay_order_id TEXT,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Create order_items table
    c.execute('''CREATE TABLE IF NOT EXISTS order_items
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 order_id INTEGER NOT NULL,
                 product_id INTEGER NOT NULL,
                 quantity INTEGER NOT NULL,
                 price REAL NOT NULL,
                 FOREIGN KEY (order_id) REFERENCES orders (id),
                 FOREIGN KEY (product_id) REFERENCES products (id))''')
    
    # Create OTP table for password reset
    c.execute('''CREATE TABLE IF NOT EXISTS otps
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 email TEXT NOT NULL,
                 otp TEXT NOT NULL,
                 expires_at TIMESTAMP NOT NULL,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert sample products if they don't exist
    c.execute("SELECT COUNT(*) FROM products")
    if c.fetchone()[0] == 0:
        sample_products = [
            ('Smartphone X', 'Latest smartphone with amazing features', 699.99, '/static/images/phone.jpg', 'Electronics', 50),
            ('Laptop Pro', 'Powerful laptop for professionals', 1299.99, '/static/images/laptop.jpg', 'Electronics', 30),
            ('Running Shoes', 'Comfortable shoes for running', 89.99, '/static/images/shoes.jpg', 'Fashion', 100),
            ('Coffee Maker', 'Brew perfect coffee every time', 49.99, '/static/images/coffee.jpg', 'Home', 40),
            ('Wireless Headphones', 'Noise cancelling headphones', 149.99, '/static/images/headphones.jpg', 'Electronics', 60)
        ]
        c.executemany('INSERT INTO products (name, description, price, image_url, category, stock) VALUES (?, ?, ?, ?, ?, ?)', sample_products)
    
    conn.commit()
    conn.close()

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Generate OTP
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

# Send OTP via Email
def send_email_otp(email, otp):
    try:
        msg = Message('Password Reset OTP', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP for password reset is: {otp}. It will expire in 10 minutes.'
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Send OTP via SMS
def send_sms_otp(phone, otp):
    try:
        message = twilio_client.messages.create(
            body=f'Your verification code is: {otp}. It will expire in 10 minutes.',
            from_=TWILIO_PHONE_NUMBER,
            to=phone
        )
        return True
    except Exception as e:
        print(f"Error sending SMS: {e}")
        return False

# Routes
@app.route('/')
def index():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products LIMIT 8').fetchall()
    conn.close()
    return render_template('index.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')
        
        conn = get_db_connection()
        # Check if email or phone already exists
        existing_user = conn.execute('SELECT * FROM users WHERE email = ? OR phone = ?', (email, phone)).fetchone()
        if existing_user:
            flash('Email or phone number already registered!', 'danger')
            conn.close()
            return render_template('register.html')
        
        # Insert new user
        conn.execute('INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
                    (name, email, phone, password))
        
        # Generate and send OTP for phone verification
        otp = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)
        conn.execute('INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
                    (email, otp, expires_at))
        
        conn.commit()
        conn.close()
        
        # Send OTP via SMS
        if send_sms_otp(phone, otp):
            session['verify_email'] = email
            flash('OTP sent to your phone for verification!', 'success')
            return redirect(url_for('verify_otp', purpose='register'))
        else:
            flash('Failed to send OTP. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/verify-otp/<purpose>', methods=['GET', 'POST'])
def verify_otp(purpose):
    if 'verify_email' not in session:
        flash('Session expired. Please try again.', 'danger')
        return redirect(url_for('register' if purpose == 'register' else 'forgot_password'))
    
    email = session['verify_email']
    
    if request.method == 'POST':
        otp = request.form['otp']
        
        conn = get_db_connection()
        otp_record = conn.execute(
            'SELECT * FROM otps WHERE email = ? AND otp = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1',
            (email, otp, datetime.now())
        ).fetchone()
        
        if otp_record:
            # OTP is valid
            if purpose == 'register':
                conn.execute('UPDATE users SET phone_verified = 1 WHERE email = ?', (email,))
                flash('Phone verified successfully! You can now login.', 'success')
            else:  # password reset
                session['reset_email'] = email
                flash('OTP verified! Please set your new password.', 'success')
                conn.close()
                return redirect(url_for('reset_password'))
            
            conn.commit()
            conn.close()
            session.pop('verify_email', None)
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired OTP!', 'danger')
            conn.close()
    
    return render_template('verify_otp.html', purpose=purpose)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password)).fetchone()
        conn.close()
        
        if user:
            if user['phone_verified']:
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Please verify your phone number first!', 'danger')
                return redirect(url_for('verify_otp', purpose='register'))
        else:
            flash('Invalid email or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!', 'info')
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Generate and send OTP via email
            otp = generate_otp()
            expires_at = datetime.now() + timedelta(minutes=10)
            
            conn.execute('INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
                        (email, otp, expires_at))
            conn.commit()
            conn.close()
            
            if send_email_otp(email, otp):
                session['verify_email'] = email
                flash('OTP sent to your email!', 'success')
                return redirect(url_for('verify_otp', purpose='password_reset'))
            else:
                flash('Failed to send OTP. Please try again.', 'danger')
        else:
            flash('Email not found!', 'danger')
            conn.close()
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash('Session expired. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))
    
    email = session['reset_email']
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('reset_password.html')
        
        conn = get_db_connection()
        conn.execute('UPDATE users SET password = ? WHERE email = ?', (password, email))
        conn.commit()
        conn.close()
        
        session.pop('reset_email', None)
        flash('Password reset successfully! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/products')
def products():
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    
    conn = get_db_connection()
    query = 'SELECT * FROM products WHERE 1=1'
    params = []
    
    if category:
        query += ' AND category = ?'
        params.append(category)
    
    if search:
        query += ' AND name LIKE ?'
        params.append(f'%{search}%')
    
    products = conn.execute(query, params).fetchall()
    categories = conn.execute('SELECT DISTINCT category FROM products').fetchall()
    conn.close()
    
    return render_template('products.html', products=products, categories=categories, 
                          selected_category=category, search_query=search)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    conn.close()
    
    if product is None:
        flash('Product not found!', 'danger')
        return redirect(url_for('products'))
    
    return render_template('product_detail.html', product=product)

@app.route('/add-to-cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash('Please login first!', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if product already in cart
    existing_item = conn.execute(
        'SELECT * FROM cart WHERE user_id = ? AND product_id = ?',
        (session['user_id'], product_id)
    ).fetchone()
    
    if existing_item:
        # Update quantity
        conn.execute(
            'UPDATE cart SET quantity = quantity + 1 WHERE user_id = ? AND product_id = ?',
            (session['user_id'], product_id)
        )
    else:
        # Add new item to cart
        conn.execute(
            'INSERT INTO cart (user_id, product_id) VALUES (?, ?)',
            (session['user_id'], product_id)
        )
    
    conn.commit()
    conn.close()
    
    flash('Product added to cart!', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash('Please login first!', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cart_items = conn.execute('''
        SELECT cart.id, products.id as product_id, products.name, products.price, 
               products.image_url, cart.quantity, (products.price * cart.quantity) as total
        FROM cart 
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = ?
    ''', (session['user_id'],)).fetchall()
    
    total_amount = sum(item['total'] for item in cart_items)
    conn.close()
    
    return render_template('cart.html', cart_items=cart_items, total_amount=total_amount)

@app.route('/update-cart/<int:cart_id>', methods=['POST'])
def update_cart(cart_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first!'})
    
    quantity = int(request.form['quantity'])
    
    conn = get_db_connection()
    conn.execute(
        'UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?',
        (quantity, cart_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/remove-from-cart/<int:cart_id>')
def remove_from_cart(cart_id):
    if 'user_id' not in session:
        flash('Please login first!', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute(
        'DELETE FROM cart WHERE id = ? AND user_id = ?',
        (cart_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    
    flash('Item removed from cart!', 'success')
    return redirect(url_for('cart'))

@app.route('/checkout')
def checkout():
    if 'user_id' not in session:
        flash('Please login first!', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cart_items = conn.execute('''
        SELECT cart.id, products.id as product_id, products.name, products.price, 
               products.image_url, cart.quantity, (products.price * cart.quantity) as total
        FROM cart 
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = ?
    ''', (session['user_id'],)).fetchall()
    
    if not cart_items:
        flash('Your cart is empty!', 'warning')
        return redirect(url_for('cart'))
    
    total_amount = sum(item['total'] for item in cart_items)
    conn.close()
    
    return render_template('checkout.html', cart_items=cart_items, total_amount=total_amount)

@app.route('/create-order', methods=['POST'])
def create_order():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first!'})
    
    conn = get_db_connection()
    
    # Get cart items
    cart_items = conn.execute('''
        SELECT cart.product_id, cart.quantity, products.price
        FROM cart 
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = ?
    ''', (session['user_id'],)).fetchall()
    
    if not cart_items:
        return jsonify({'success': False, 'message': 'Your cart is empty!'})
    
    total_amount = sum(item['price'] * item['quantity'] for item in cart_items)
    
    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        'amount': int(total_amount * 100),  # Convert to paise
        'currency': 'INR',
        'payment_capture': 1
    })
    
    # Create order in database
    order_id = conn.execute(
        'INSERT INTO orders (user_id, total_amount, razorpay_order_id) VALUES (?, ?, ?)',
        (session['user_id'], total_amount, razorpay_order['id'])
    ).lastrowid
    
    # Add order items
    for item in cart_items:
        conn.execute(
            'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
            (order_id, item['product_id'], item['quantity'], item['price'])
        )
    
    # Clear cart
    conn.execute('DELETE FROM cart WHERE user_id = ?', (session['user_id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'order_id': razorpay_order['id'],
        'amount': int(total_amount * 100),
        'currency': 'INR',
        'key': RAZORPAY_KEY_ID
    })
    
  
@app.route('/check-payment-status/<order_id>')
def check_payment_status(order_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first!'})
    
    conn = get_db_connection()
    order = conn.execute(
        'SELECT status FROM orders WHERE razorpay_order_id = ? AND user_id = ?',
        (order_id, session['user_id'])
    ).fetchone()
    conn.close()
    
    if order:
        return jsonify({'status': order['status']})
    else:
        return jsonify({'status': 'unknown'})

@app.route('/payment-success')
def payment_success():
    order_id = request.args.get('razorpay_order_id')
    
    conn = get_db_connection()
    conn.execute(
        'UPDATE orders SET status = "completed" WHERE razorpay_order_id = ?',
        (order_id,)
    )
    conn.commit()
    conn.close()
    
    flash('Payment successful! Your order has been placed.', 'success')
    return redirect(url_for('index'))

@app.route('/payment-failure')
def payment_failure():
    flash('Payment failed. Please try again.', 'danger')
    return redirect(url_for('checkout'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login first!', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    orders = conn.execute('''
        SELECT orders.*, COUNT(order_items.id) as item_count 
        FROM orders 
        LEFT JOIN order_items ON orders.id = order_items.order_id 
        WHERE orders.user_id = ? 
        GROUP BY orders.id 
        ORDER BY orders.created_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('profile.html', user=user, orders=orders)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)