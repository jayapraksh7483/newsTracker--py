from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import datetime, timedelta, timezone
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename
import re
import logging
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ------------ CONFIG ------------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",  # For production (e.g., Render PostgreSQL)
    f"mysql+pymysql://root:{os.environ.get('DB_PASSWORD', 'NewPassword123')}@localhost/news_db"  # Local MySQL
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email configuration
app.config['SMTP_SERVER'] = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
app.config['SMTP_PORT'] = int(os.environ.get('SMTP_PORT', 587))
app.config['SMTP_EMAIL'] = os.environ.get('SMTP_EMAIL', 'via18352@gmail.com')
app.config['SMTP_PASSWORD'] = os.environ.get('SMTP_PASSWORD', 'mwbb migc kbij qscg')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Logging setup
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,  # INFO for production to capture more details
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ------------ ERROR HANDLING ------------
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    flash("File is too large. Maximum allowed size is 16 MB.")
    return redirect(request.url)

# ------------ MODELS ------------
logged_in_users = set()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)  # email
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Changed to Boolean for PostgreSQL compatibility
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)
    date_registered = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    posts = db.relationship('Post', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='comment_user', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(200))
    media_url = db.Column(db.String(200))
    media_type = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='uq_user_post_like'),)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ------------ HELPERS ------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def is_email(identifier):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', identifier) is not None

def send_otp_email(email, otp):
    try:
        if not app.config['SMTP_EMAIL'] or not app.config['SMTP_PASSWORD']:
            logging.error(f"SMTP not configured for {email}")
            return False
        recipient = email
        msg = MIMEText(f'Your OTP for password reset is: {otp}\nIt is valid for 10 minutes.')
        msg['Subject'] = 'News Tracker Password Reset OTP'
        msg['From'] = app.config['SMTP_EMAIL']
        msg['To'] = recipient
        server = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT'])
        server.starttls()
        server.login(app.config['SMTP_EMAIL'], app.config['SMTP_PASSWORD'])
        server.sendmail(app.config['SMTP_EMAIL'], recipient, msg.as_string())
        server.quit()
        logging.info(f"OTP email sent successfully to {recipient}")
        return True
    except smtplib.SMTPAuthenticationError as auth_error:
        logging.error(f"SMTP Authentication failed for {email}: {auth_error}")
        return False
    except Exception as e:
        logging.error(f"Error sending email to {email}: {str(e)}")
        return False

# ------------ ROUTES ------------
@app.route('/')
def index():
    category = request.args.get('category')
    city = request.args.get('city')
    query = db.session.query(Post).order_by(Post.date_posted.desc())
    if category:
        query = query.filter_by(category=category)
    if city:
        query = query.filter_by(city=city)
    posts = query.all()
    latest_posts = db.session.query(Post).order_by(Post.date_posted.desc()).limit(5).all()
    if current_user.is_authenticated:
        for post in posts:
            existing_like = db.session.query(Like).filter_by(user_id=current_user.id, post_id=post.id).first()
            post.user_liked = existing_like is not None
    return render_template('index.html', posts=posts, latest_posts=latest_posts, category=category, city=city)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = db.session.query(User).filter_by(username=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            logged_in_users.add(user.id)
            return redirect(url_for('index'))
        flash("Invalid email or password.")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if not is_email(email):
            flash("Invalid email.")
            return render_template('register.html')
        if db.session.query(User).filter_by(username=email).first():
            flash("Email already registered.")
        else:
            is_admin = email == 'admin@example.com'
            user = User(
                username=email,
                password_hash=generate_password_hash(password),
                is_admin=is_admin,
                date_registered=datetime.now(timezone.utc).replace(tzinfo=None)
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            logged_in_users.add(user.id)
            return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        if not is_email(email):
            flash("Invalid email.")
            return render_template('forgot.html')
        user = db.session.query(User).filter_by(username=email).first()
        if user:
            otp = secrets.token_hex(3).upper()
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=10)
            db.session.commit()
            sent = send_otp_email(email, otp)
            if sent:
                flash("An OTP has been sent to your email. Check inbox/spam.")
            else:
                flash("Failed to send OTP. Please verify email configuration and try again.")
                return render_template('forgot.html')
            session['reset_email'] = email
            session['reset_otp'] = otp
            return redirect(url_for('reset', token=token))
        else:
            flash("Email not found.")
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    user = db.session.query(User).filter_by(reset_token=token).first()
    if not user or user.reset_token_expiry is None or user.reset_token_expiry < datetime.now(timezone.utc).replace(tzinfo=None):
        flash("Invalid or expired reset token.")
        return redirect(url_for('forgot'))
    if request.method == 'POST':
        otp = request.form['otp']
        password = request.form['password']
        if 'reset_otp' in session and session['reset_otp'] == otp and session.get('reset_email') == user.username:
            user.password_hash = generate_password_hash(password)
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
            session.pop('reset_otp', None)
            session.pop('reset_email', None)
            flash("Password reset successfully. Please log in.")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP.")
    return render_template('reset.html', token=token)

@app.route('/logout')
@login_required
def logout():
    logged_in_users.discard(current_user.id)
    logout_user()
    return redirect(url_for('index'))

@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        city = request.form['city']
        url = request.form.get('url')
        media_url = request.form.get('media_url')
        media_type = request.form.get('media_type') or None
        try:
            if 'media_file' in request.files:
                file = request.files['media_file']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    media_url = f'uploads/{filename}'
                    ext = filename.rsplit('.', 1)[1].lower()
                    media_type = 'image' if ext in {'png', 'jpg', 'jpeg', 'gif'} else 'video'
                elif file.filename:
                    flash("Invalid file format. Only PNG, JPG, JPEG, GIF, MP4, WebM allowed.")
                    return redirect(url_for('add_post'))
            post = Post(
                title=title,
                description=description,
                category=category,
                city=city,
                url=url,
                media_url=media_url,
                media_type=media_type,
                user_id=current_user.id
            )
            db.session.add(post)
            db.session.commit()
            flash("Post added successfully.")
            return redirect(url_for('my_posts'))
        except Exception as e:
            flash(f"Error uploading file: {str(e)}")
            return redirect(url_for('add_post'))
    return render_template('add_post.html')

@app.route('/my_posts')
@login_required
def my_posts():
    posts = db.session.query(Post).filter_by(user_id=current_user.id).order_by(Post.date_posted.desc()).all()
    return render_template('my_posts.html', posts=posts)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    if post.user_id != current_user.id:
        flash("You can only edit your own posts.")
        return redirect(url_for('my_posts'))
    if request.method == 'POST':
        try:
            post.title = request.form['title']
            post.description = request.form['description']
            post.category = request.form['category']
            post.city = request.form['city']
            post.url = request.form.get('url')
            post.media_url = request.form.get('media_url')
            post.media_type = request.form.get('media_type') or None
            if 'media_file' in request.files:
                file = request.files['media_file']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    post.media_url = f'uploads/{filename}'
                    ext = filename.rsplit('.', 1)[1].lower()
                    post.media_type = 'image' if ext in {'png', 'jpg', 'jpeg', 'gif'} else 'video'
                elif file.filename:
                    flash("Invalid file format. Only PNG, JPG, JPEG, GIF, MP4, WebM allowed.")
                    return redirect(url_for('edit_post', post_id=post_id))
            db.session.commit()
            flash("Post updated successfully.")
            return redirect(url_for('my_posts'))
        except Exception as e:
            flash(f"Error uploading file: {str(e)}")
            return redirect(url_for('edit_post', post_id=post_id))
    return render_template('add_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    if post.user_id != current_user.id and not current_user.is_admin:
        flash("You can only delete your own posts or posts as an admin.")
        return redirect(url_for('my_posts'))
    db.session.query(Comment).filter_by(post_id=post.id).delete(synchronize_session=False)
    db.session.query(Like).filter_by(post_id=post.id).delete(synchronize_session=False)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully.")
    return redirect(url_for('my_posts') if not current_user.is_admin else url_for('admin'))

@app.route('/like/<int:post_id>', methods=['GET', 'POST'])
@login_required
def like_post(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    existing = db.session.query(Like).filter_by(user_id=current_user.id, post_id=post.id).first()
    if existing:
        return {'success': True, 'alreadyLiked': True, 'likes': post.likes}
    like = Like(user_id=current_user.id, post_id=post.id)
    db.session.add(like)
    post.likes += 1
    db.session.commit()
    return {'success': True, 'alreadyLiked': False, 'likes': post.likes}

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    comment = Comment(content=request.form['comment'], user_id=current_user.id, post_id=post.id)
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = db.session.get(Comment, comment_id)
    if comment is None:
        abort(404)
    if comment.user_id != current_user.id and not current_user.is_admin:
        flash("You can only delete your own comments or comments as an admin.")
        return redirect(url_for('view_post', post_id=comment.post_id))
    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted successfully.")
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Admin access only.")
        return redirect(url_for('index'))
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.is_admin:
        flash("Cannot delete admin users.")
        return redirect(url_for('admin'))
    db.session.query(Post).filter_by(user_id=user.id).delete(synchronize_session=False)
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} and all their posts have been deleted successfully.")
    return redirect(url_for('admin'))

@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    user_liked = False
    if current_user.is_authenticated:
        existing_like = db.session.query(Like).filter_by(user_id=current_user.id, post_id=post.id).first()
        user_liked = existing_like is not None
    return render_template('view_post.html', post=post, user_liked=user_liked)

@app.route('/category/<category_name>')
def category_news(category_name):
    posts = db.session.query(Post).filter_by(category=category_name).order_by(Post.date_posted.desc()).all()
    if current_user.is_authenticated:
        for post in posts:
            existing_like = db.session.query(Like).filter_by(user_id=current_user.id, post_id=post.id).first()
            post.user_liked = existing_like is not None
    return render_template('category_news.html', posts=posts, category=category_name)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Admin access only.")
        return redirect(url_for('index'))
    users = db.session.query(User).all()
    posts = db.session.query(Post).order_by(Post.date_posted.desc()).all()
    return render_template('admin.html', users=users, posts=posts, logged_in_users_count=len(logged_in_users))

# ------------ ENTRYPOINT ------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(host='0.0.0.0', port=5000)  # No debug=True for production readiness