# Import the required libraries and packages
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from sqlalchemy import desc
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import os
import hashlib
import pyotp
import cv2
import json
import face_recognition

# Configure the Flask application
app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Configure the SQLAlchemy database
db = SQLAlchemy(app)

# Configure the Flask-Login extension
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

# Define the User model for the database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    logs = db.relationship('Log', backref='user', lazy=True, uselist=False, order_by='Log.datetime.desc()')

# Define the Log model for the database
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(128), nullable=False)
    datetime = db.Column(db.DateTime, nullable=False, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Define the index route for the application
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@login_manager.user_loader
def load_user(user):
    return User.query.get(int(user))

# Define the login route for the application
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        # Retrieve the form data
        username = request.form['username']
        password = request.form['password']
        # Check if the user is valid
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('Invalid username or password!')
            return redirect(url_for('login'))
        # Check if the password is valid
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), user.salt.encode('utf-8'), 100000)
        if hashed_password != user.password:
            flash('Invalid username or password!')
            return redirect(url_for('login'))
        # Log in the user
        login_user(user)
        log = Log(description='Login successful!', user_id=current_user.id)
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# Define the registration route for the application
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        # Retrieve the form data
        username = request.form['username']

        # Retrieve the form data
        username = request.form['username']
        password = request.form['password']
        otp_secret = pyotp.random_base32()
        # Hash the password with salt
        salt = os.urandom(16).hex()
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        # Create a new user
        user = User(username=username, password=hashed_password, salt=salt, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully!')
        return redirect(url_for('login'))
    return render_template('register.html')


#Define the logout route for the application
@app.route('/logout')
@login_required
def logout():
    log = Log(description='Logout successful!', user_id=current_user.id)
    db.session.add(log)
    db.session.commit()
    logout_user()
    return redirect(url_for('index'))

# Define the dashboard route for the application
@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        logs = Log.query.filter_by(user_id=current_user.get_id()).order_by(Log.datetime.desc()).limit(10).all()
    else:
        logs = Log.query.order_by(Log.datetime.desc()).limit(10).all()
    return render_template('dashboard.html', logs=logs)


# Define the admin route for the application
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    users = User.query.all()
    logs = Log.query.order_by(Log.datetime.desc()).limit(10).all()
    return render_template('admin.html', users=users, logs=logs)

# Define the delete user route for the application
@app.route('/delete-user/int:id')
@login_required
def delete_user(id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!')
    return redirect(url_for('admin'))

# Define the edit user route for the application
@app.route('/edit-user/int:id', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    user = User.query.get(id)
    if request.method == 'POST':
        # Retrieve the form data
        user.username = request.form['username']
        if request.form.get('is_admin') == 'on':
            user.is_admin = True
        else:
            user.is_admin = False
        # Update the user
        db.session.commit()
        flash('User updated successfully!')
        return redirect(url_for('admin'))
    return render_template('edit-user.html', user=user)

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Define the upload image route for the application
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # Retrieve the file data
        file = request.files['file']
        if file and allowed_file(file.filename) == False:
            resp = jsonify({'message' : 'Allowed file types are png, jpg, jpeg'})
            resp.status_code = 400
            return resp
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # Save the file
        file.save(filepath)
        flash('File uploaded successfully!')
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

# Define the face recognition route for the application
@app.route('/face-recognition', methods=['GET', 'POST'])
@login_required
def face_recognition():
    if request.method == 'POST':
        # Retrieve the image data
        image = request.files['image']
        image_data = image.read()
        # Load the image and detect the face
        face_detector = FaceDetector()
        faces = face_detector.detect_faces(image_data)
        # If no faces detected, show error message
        if not faces:
            flash('No faces detected!')
            return redirect(url_for('face_recognition'))
        # If multiple faces detected, show error message
        if len(faces) > 1:
            flash('Multiple faces detected!')
            return redirect(url_for('face_recognition'))
        # Extract the face embedding
        face_embedding = face_detector.extract_embedding(image_data, faces[0])
        # Search for a matching face in the database
        user = User.query.filter_by(face_embedding=face_embedding).first()
        if user is None:
            flash('No matching face found!')
            return redirect(url_for('face_recognition'))
        # Authenticate the user
        authenticated = authenticate_user(user)
        if authenticated:
            log = Log(description='Face recognition successful!', user_id=user.id)
            db.session.add(log)
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            log = Log(description='Face recognition failed!', user_id=user.id)
            db.session.add(log)
            db.session.commit()
            flash('Face recognition failed!')
            return redirect(url_for('face_recognition'))
    return render_template('face-recognition.html')


with app.app_context():
    db.create_all()
    users = User.query.all()
    print(users)


if __name__ == 'main':
    app.run(debug=True)