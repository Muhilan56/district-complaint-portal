import random
from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask import Flask, render_template, request, jsonify

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


# Sample complaints database
complaints = {}
complaint_id_counter = 1

responses = {
    "greeting": [
        "Hello! How can I assist you with your complaint today?",
        "Hi there! What issue are you facing?",
        "Greetings! How can I help you?",
        "Welcome! Do you need assistance with a complaint?",
        "Hello! What seems to be the problem?"
    ],
    "status": [
        "Please provide your complaint ID to check the status.",
        "I can check the status for you! What is your complaint ID?",
        "Kindly share your complaint ID to proceed.",
        "Checking status requires your complaint ID. Could you provide it?",
        "To retrieve your complaint status, I'll need your complaint ID."
    ],
    "new_complaint": [
        "Please describe your issue, and I will register a complaint for you.",
        "I can help you file a complaint. What seems to be the problem?",
        "Tell me about your issue, and I'll register it for you.",
        "What problem are you facing? I’ll make sure to log it for you.",
        "Feel free to describe your issue, and I'll take note of it."
    ],
    "thanks": [
        "You're welcome! Have a great day!",
        "Glad I could help!",
        "Anytime! If you need further assistance, let me know.",
        "You're most welcome! Reach out if you need anything else.",
        "No problem! Wishing you a wonderful day ahead."
    ],
    "fallback": [
        "I'm sorry, I didn't understand that. Can you please rephrase?",
        "Could you clarify that? I'm here to help!",
        "I'm not sure I follow. Could you explain differently?",
        "That doesn’t seem clear to me. Could you rephrase it?",
        "I’m having trouble understanding. Could you say it another way?"
    ],
    "laws": [
        "Consumer protection laws ensure your rights when filing complaints.",
        "Legal frameworks provide safety measures for consumers.",
        "Did you know? Many laws protect your rights against unfair practices.",
        "Laws exist to make sure your complaints are heard and resolved fairly.",
        "Consumer rights include refund policies, safety standards, and fair treatment."
    ],
    "common_complaints": [
        "Frequent complaints include service delays, faulty products, and billing errors.",
        "People often report issues like poor customer service and fraud.",
        "Common complaints involve contract disputes, defective goods, and misinformation.",
        "Issues related to delivery failures and incorrect charges are commonly reported.",
        "Many customers file complaints about unauthorized deductions and data breaches."
    ]
}

def get_bot_response(user_input):
    global complaint_id_counter
    user_input = user_input.lower()
    
    if "hello" in user_input or "hi" in user_input:
        return random.choice(responses["greeting"])
    elif "status" in user_input:
        return random.choice(responses["status"])
    elif "complaint" in user_input or "issue" in user_input:
        return random.choice(responses["new_complaint"])
    elif "thank" in user_input:
        return random.choice(responses["thanks"])
    elif "law" in user_input or "rights" in user_input:
        return random.choice(responses["laws"])
    elif "common" in user_input or "frequent" in user_input:
        return random.choice(responses["common_complaints"])
    else:
        return random.choice(responses["fallback"])

@app.route("/chat")
def comment():
    return render_template("chat.html")

@app.route("/get", methods=["GET", "POST"])
def chat():
    user_message = request.form["msg"]
    bot_response = get_bot_response(user_message)
    return jsonify({"response": bot_response})

@app.route("/submit_complaint", methods=["POST"])
def submit_complaint():
    global complaint_id_counter
    data = request.json
    complaint_text = data.get("complaint")
    
    if complaint_text:
        complaint_id = complaint_id_counter
        complaints[complaint_id] = {"text": complaint_text, "status": "Pending"}
        complaint_id_counter += 1
        return jsonify({"message": "Complaint registered successfully!", "complaint_id": complaint_id})
    else:
        return jsonify({"error": "Complaint text is required."}), 400

@app.route("/check_status/<int:complaint_id>", methods=["GET"])
def check_status(complaint_id):
    if complaint_id in complaints:
        return jsonify({"complaint_id": complaint_id, "status": complaints[complaint_id]["status"]})
    else:
        return jsonify({"error": "Complaint ID not found."}), 404



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
