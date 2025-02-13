from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask import Flask, render_template, request, jsonify
import torch
from transformers import GPT2Tokenizer, GPT2LMHeadModel

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complaints.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'daminmain@gmail.com'  # Change this
app.config['MAIL_PASSWORD'] = 'kpqtxqskedcykwjz'  # Change this
bcrypt = Bcrypt(app)
mail = Mail(app)


tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
model = GPT2LMHeadModel.from_pretrained("gpt2")

# Predefined responses for greetings
greeting_responses = {
    "hi": "Hi there! How can I assist you?",
    "hai": "Hello! What can I do for you?",
    "hello": "Hey! How's it going?",
    "hey": "Hey! Need any help?",
}

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(255), nullable=False)


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default="Pending")



def generate_response(prompt):
    prompt_lower = prompt.lower().strip()

    # Check if input is a greeting
    if prompt_lower in greeting_responses:
        return greeting_responses[prompt_lower]

    # Otherwise, use GPT-2 to generate a response
    inputs = tokenizer.encode(prompt, return_tensors="pt")
    outputs = model.generate(inputs, max_length=150, pad_token_id=tokenizer.eos_token_id)
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return response

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')  # Use .get() to prevent KeyError
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Username or email already registered!", "danger")
            return redirect(url_for('register'))

        user = User(username=username, email=email, phone=phone, password=password)
        db.session.add(user)
        db.session.commit()

        # Send Email Notification
        msg = Message("Registration Successful", sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Hello {username},\n\nYour account has been successfully registered."
        mail.send(msg)

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if it's an admin login
        if email == "admin@gmail.com" and password == "admin123":
            session['admin'] = True  # Store admin session
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard'))

        # Regular user login
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password!", "danger")
    
    return render_template('login.html')


@app.route("/chat1")
def index():
    return render_template("chat.html")

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()  
    user_input = data.get("message", "").strip()

    if not user_input:
        return jsonify({"error": "Message is required"}), 400

    response = generate_response(user_input)
    return jsonify({"reply": response})


@app.route('/logout')
def logout():
    logout_user()
    session.pop('admin', None)
    return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    complaints = Complaint.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', complaints=complaints)

@app.route('/complaint', methods=['GET', 'POST'])
@login_required
def complaint():
    if request.method == 'POST':
        category = request.form['category']
        description = request.form['description']

        new_complaint = Complaint(user_id=current_user.id, category=category, description=description)
        db.session.add(new_complaint)
        db.session.commit()

        # Send email to the user
        user_email = current_user.email  # Get logged-in user's email
        msg = Message("Complaint Submission Confirmation", sender=app.config['MAIL_USERNAME'], recipients=[user_email])
        msg.body = f"Dear {current_user.username},\n\nYour complaint has been successfully submitted.\n\nCategory: {category}\nDescription: {description}\n\nWe will review your complaint and update you shortly.\n\nBest regards,\nComplaint Support Team"
        mail.send(msg)

        flash("Complaint submitted successfully! A confirmation email has been sent to your registered email.", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('complaint.html')



@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin' not in session:
        flash("Admin login required", "danger")
        return redirect(url_for('login'))

    complaints = Complaint.query.all()
    return render_template('admin_dashboard.html', complaints=complaints)

@app.route('/admin/update_status/<int:complaint_id>', methods=['POST'])
def update_status(complaint_id):
    if 'admin' not in session:
        flash("Admin login required", "danger")
        return redirect(url_for('login'))

    complaint = Complaint.query.get_or_404(complaint_id)
    complaint.status = "Completed"
    db.session.commit()

    # Notify the user via email
    user = User.query.get(complaint.user_id)
    msg = Message("Complaint Status Updated", sender="your_email@gmail.com", recipients=[user.email])
    msg.body = f"Your complaint (ID: {complaint.id}) has been marked as 'Completed'."
    mail.send(msg)

    flash("Complaint status updated!", "success")
    return redirect(url_for('admin_dashboard'))


@app.route('/loggedin_users')
def loggedin_users():
    users = User.query.all()  # Fetch all users
    return render_template('loggedin_users.html', users=users)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
