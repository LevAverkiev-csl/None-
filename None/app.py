import eventlet

eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import PasswordField, SubmitField, StringField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Length
from datetime import datetime, timedelta, timezone
from flask_migrate import Migrate
from flask_wtf.csrf import generate_csrf, validate_csrf, CSRFError
from sqlalchemy import or_, and_, func
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.hybrid import hybrid_property
import uuid
import mimetypes
from PIL import Image
from flask_cors import CORS
import io
import base64
import json
import logging
import traceback
import os
from sqlalchemy.exc import OperationalError, ProgrammingError, IntegrityError
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_caching import Cache

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_url_path='/static')

# Конфигурация приложения
app.config.update(
    UPLOAD_FOLDER='static/posts',
    AVATAR_UPLOAD_FOLDER='static/uploads/avatars',
    MESSAGE_UPLOAD_FOLDER='static/uploads/messages',
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm', 'mp3', 'wav', 'pdf', 'pptx'},
    SQLALCHEMY_DATABASE_URI='sqlite:///ruspost.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY='1363916e456d2668fc3ab57f5006d681996bff4fb5396d94',
    MAX_CONTENT_LENGTH=100 * 1024 * 1024,
    WTF_CSRF_TIME_LIMIT=3600,
    CSRF_COOKIE_NAME='csrf_token',
    CSRF_HEADER_NAME='X-CSRFToken',
    CSRF_COOKIE_SECURE=False,
    CSRF_COOKIE_HTTPONLY=True,
    CSRF_COOKIE_SAMESITE='Lax'
)

# Инициализация расширений
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})
cache.init_app(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "X-CSRFToken"]
    }
})

login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Модели данных
class UserLink(db.Model):
    __tablename__ = 'user_links'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    order = db.Column(db.Integer, default=0)


class SearchHistory(db.Model):
    __tablename__ = 'search_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    search_query = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Исправляем обратную ссылку
    user = db.relationship('User', backref='search_history_entries')

class Chat(db.Model):
    __tablename__ = 'chats'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, index=True, default=datetime.now(timezone.utc))
    last_message_at = db.Column(db.DateTime)

    def get_other_user(self, current_user_id):
        if current_user_id == self.user1_id:
            return db.session.get(User, self.user2_id)
        return db.session.get(User, self.user1_id)

    def update_last_message_time(self):
        self.last_message_at = datetime.now(timezone.utc)
        db.session.commit()


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'))
    sent_at = db.Column(db.DateTime, index=True, default=datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default=False)

    def mark_as_read(self):
        self.is_read = True
        db.session.commit()

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'sender_id': self.sender_id,
            'chat_id': self.chat_id,
            'sent_at': self.sent_at.isoformat(),
            'is_read': self.is_read
        }


class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False, index=True)  # Добавляем индекс
    media_path = db.Column(db.String(200), nullable=True)
    tags = db.Column(db.String(200))
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def likes_count(self):
        return self.likes.count()

    @property
    def comments_count(self):
        return self.comments.count()

    def is_liked_by(self, user):
        if not user or not user.is_authenticated:
            return False
        return self.likes.filter_by(user_id=user.id).first() is not None

    def is_bookmarked_by(self, user):
        if not user or not user.is_authenticated:
            return False
        return self.bookmarked_by.filter_by(id=user.id).first() is not None

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'author': {
                'id': self.author.id,
                'username': self.author.username,
                'avatar': self.author.avatar
            },
            'created_at': self.created_at.isoformat(),
            'likes_count': self.likes_count,
            'comments_count': self.comments_count,
            'is_liked': self.is_liked_by(current_user) if current_user.is_authenticated else False,
            'is_bookmarked': self.is_bookmarked_by(current_user) if current_user.is_authenticated else False
        }

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='comments')

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'post_id': self.post_id,
            'user_id': self.user_id,
            'user': {
                'id': self.user.id,
                'username': self.user.username,
                'avatar': self.user.avatar
            },
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Like(db.Model):
    __tablename__ = 'likes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default=False)
    related_post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=True)

    def mark_as_read(self):
        self.is_read = True
        db.session.commit()


class Achievement(db.Model):
    __tablename__ = 'achievements'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    threshold = db.Column(db.Integer, nullable=False)
    achieved_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('user_id', 'type', 'threshold', name='unique_achievement'),)


# Ассоциативная таблица для закладок
user_bookmarked_posts = db.Table('user_bookmarked_posts',
                                 db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
                                 db.Column('post_id', db.Integer, db.ForeignKey('posts.id'), primary_key=True)
                                 )


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True, index=True)  # Добавляем индекс
    email = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(128))
    avatar = db.Column(db.String(200), default='default.jpg')
    about_me = db.Column(db.String(500))
    last_seen = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    is_online = db.Column(db.Boolean, default=False)
    show_links = db.Column(db.Boolean, default=True)
    dark_mode = db.Column(db.Boolean, default=False)
    total_likes = db.Column(db.Integer, default=0)
    total_comments = db.Column(db.Integer, default=0)
    total_followers = db.Column(db.Integer, default=0)
    total_posts = db.Column(db.Integer, default=0)

    # Связи
    links = db.relationship('UserLink', backref='user', cascade='all, delete-orphan')
    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    achievements = db.relationship('Achievement', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    searches = db.relationship('SearchHistory', backref='searcher', lazy='dynamic')

    following = db.relationship('User',
                                secondary='subscriptions',
                                primaryjoin='Subscription.follower_id==User.id',
                                secondaryjoin='Subscription.followed_id==User.id',
                                backref=db.backref('followers', lazy='dynamic'),
                                lazy='dynamic')

    initiated_chats = db.relationship('Chat',
                                      foreign_keys='Chat.user1_id',
                                      backref='user1',
                                      lazy='dynamic',
                                      cascade='all, delete-orphan')

    received_chats = db.relationship('Chat',
                                     foreign_keys='Chat.user2_id',
                                     backref='user2',
                                     lazy='dynamic',
                                     cascade='all, delete-orphan')

    sent_messages = db.relationship('Message',
                                    foreign_keys='Message.sender_id',
                                    backref='sender',
                                    lazy='dynamic',
                                    cascade='all, delete-orphan')

    bookmarked_posts = db.relationship('Post',
                                       secondary=user_bookmarked_posts,
                                       backref=db.backref('bookmarked_by', lazy='dynamic'),
                                       lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_following(self, user):
        return self.following.filter(
            Subscription.followed_id == user.id  # Убираем .c
        ).first() is not None

    def follow(self, user):
        if not self.is_following(user):
            sub = Subscription(follower_id=self.id, followed_id=user.id)
            db.session.add(sub)
            user.total_followers += 1
            db.session.commit()

    def unfollow(self, user):
        sub = Subscription.query.filter_by(
            follower_id=self.id,
            followed_id=user.id
        ).first()
        if sub:
            db.session.delete(sub)
            if user.total_followers > 0:
                user.total_followers -= 1
            db.session.commit()

    @property
    def status(self):
        if self.is_online:
            return "online"
        elif datetime.now(timezone.utc) - self.last_seen < timedelta(minutes=5):
            return "recently"
        return "offline"

    def update_last_seen(self):
        self.last_seen = datetime.now(timezone.utc)
        db.session.commit()

    def toggle_bookmark(self, post):
        if self.is_bookmarking(post):
            self.bookmarked_posts.remove(post)
            return False
        else:
            self.bookmarked_posts.append(post)
            return True

    def is_bookmarking(self, post):
        return post in self.bookmarked_posts

    # Исправленные счетчики
    @property
    def actual_total_posts(self):
        return self.posts.count()

    @property
    def actual_total_followers(self):
        return self.followers.count()

    @property
    def actual_total_following(self):
        return self.following.count()

    @property
    def actual_total_likes(self):
        return self.likes.count()

    @property
    def actual_total_comments(self):
        return Comment.query.filter_by(user_id=self.id).count()

    @property
    def bookmarks_count(self):
        return self.bookmarked_posts.count()

    def update_counters(self):
        """Обновляет все счетчики"""
        self.total_posts = self.actual_total_posts
        self.total_followers = self.actual_total_followers
        self.total_likes = self.actual_total_likes
        self.total_comments = self.actual_total_comments
        db.session.commit()

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'avatar': self.avatar,
            'status': self.status,
            'about_me': self.about_me,
            'total_posts': self.actual_total_posts,
            'total_followers': self.actual_total_followers,
            'total_following': self.actual_total_following,
            'total_likes': self.actual_total_likes,
            'total_comments': self.actual_total_comments
        }


# Формы
class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Текущий пароль', validators=[DataRequired()])
    new_password1 = PasswordField('Новый пароль', validators=[DataRequired()])
    new_password2 = PasswordField('Повторите новый пароль',
                                  validators=[DataRequired(), EqualTo('new_password1')])
    submit = SubmitField('Изменить пароль')


class PostForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Содержание', validators=[DataRequired()])
    submit = SubmitField('Опубликовать')


# Функция форматирования времени
@app.template_filter('format_time')
def format_time(dt):
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt

    if not dt:
        return ""

    now = datetime.now(timezone.utc)
    diff = now - dt

    if diff.days > 365:
        return dt.strftime('%d %b %Y')
    elif diff.days > 7:
        return dt.strftime('%d %b')
    elif diff.days > 0:
        return f"{diff.days} д. назад"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600} ч. назад"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60} мин. назад"
    return "только что"


# Обработчики ошибок
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.error(f"CSRF Error: {e}")
    return jsonify({"success": False, "error": "CSRF token invalid"}), 400


@app.errorhandler(404)
def page_not_found(e):
    logger.error(f"404 Error: {e}")
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 Error: {e}")
    return render_template('500.html'), 500


@app.errorhandler(OperationalError)
@app.errorhandler(ProgrammingError)
@app.errorhandler(IntegrityError)
def handle_db_error(e):
    logger.error(f"Database error: {str(e)}")
    try:
        db.create_all()
        logger.info("Database tables created successfully after error")
        flash("Database was automatically updated. Please try again.", 'info')
        return redirect(request.url)
    except Exception as create_error:
        logger.error(f"Database creation failed: {str(create_error)}")
        return render_template('error.html', error="Database error"), 500


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.after_request
def log_after(response):
    logger.info(f"{request.method} {request.path} - {response.status_code}")
    return response

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Маршруты
@app.route('/')
def index():
    try:
        sort_by = request.args.get('sort', 'new')

        if sort_by == 'popular':
            posts = (Post.query
                     .options(joinedload(Post.author))
                     .outerjoin(Like)
                     .group_by(Post.id)
                     .order_by(db.func.count(Like.id).desc())
                     .all())
        elif sort_by == 'hot':
            posts = (Post.query
                     .options(joinedload(Post.author))
                     .order_by(Post.hotness.desc())
                     .all())
        else:
            posts = (Post.query
                     .options(joinedload(Post.author))
                     .order_by(Post.created_at.desc())
                     .all())

        return render_template(
            'index.html',
            posts=posts,
            current_user=current_user,
            user=current_user if current_user.is_authenticated else None,
            sort_by=sort_by
        )

    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        flash('Произошла ошибка при загрузке постов', 'error')
        return render_template('index.html', posts=[], error=str(e))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            user.is_online = True
            db.session.commit()
            return redirect(url_for('index'))
        flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято', 'danger')
            return redirect(url_for('register'))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    current_user.last_seen = datetime.now(timezone.utc)
    db.session.commit()
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()

    user.total_posts = user.posts.count()
    user.total_followers = user.followers.count()
    db.session.commit()

    posts = Post.query.filter_by(author=user) \
        .order_by(Post.created_at.desc()) \
        .all()

    is_subscribed = current_user.is_authenticated and \
                    current_user.is_following(user)

    return render_template('profile.html',
                           user=user,
                           posts=posts,
                           is_subscribed=is_subscribed,
                           csrf_token=generate_csrf())


@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html',
                           post=post,
                           like_count=post.likes.count(),
                           comment_count=post.comments.count(),
                           comments=post.comments.all())


@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        try:
            content = request.form.get('content', '').strip()
            tags = request.form.get('tags', '').strip()
            file = request.files.get('file')
            filename = None

            # Валидация контента
            if not content:
                flash('Текст поста не может быть пустым', 'error')
                return redirect(url_for('create_post'))

            # Обработка файла
            if file and file.filename != '':
                allowed_extensions = {'jpg', 'jpeg', 'png', 'gif', 'mp4', 'webm', 'mp3', 'wav'}
                if '.' not in file.filename or file.filename.split('.')[-1].lower() not in allowed_extensions:
                    flash('Недопустимый тип файла', 'error')
                    return redirect(url_for('create_post'))

                filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(save_path)

                # Дополнительная валидация изображений
                if filename.lower().split('.')[-1] in ['jpg', 'jpeg', 'png', 'gif']:
                    try:
                        img = Image.open(save_path)
                        img.verify()
                    except Exception as e:
                        os.remove(save_path)
                        flash('Загруженный файл поврежден', 'error')
                        return redirect(url_for('create_post'))

            # Создание поста
            new_post = Post(
                content=content,
                tags=tags,
                media_path=filename,
                author_id=current_user.id
            )

            db.session.add(new_post)
            current_user.total_posts += 1
            db.session.commit()

            flash('Пост успешно создан!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            logger.error(f'Ошибка создания поста: {str(e)}')
            flash(f'Ошибка: {str(e)}', 'error')

    return render_template('create_post.html')


@app.route('/delete_account/<int:user_id>', methods=['POST'])
@login_required
def delete_account(user_id):
    if current_user.id != user_id:
        abort(403)
    try:
        Post.query.filter_by(author_id=user_id).delete()
        Like.query.filter_by(user_id=user_id).delete()
        Comment.query.filter_by(user_id=user_id).delete()
        Subscription.query.filter(or_(
            Subscription.follower_id == user_id,
            Subscription.followed_id == user_id
        )).delete()
        Notification.query.filter_by(user_id=user_id).delete()

        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Ваш аккаунт успешно удален.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        logger.error(f'Ошибка удаления аккаунта: {str(e)}')
        flash('Не удалось удалить аккаунт', 'error')
        return redirect(url_for('settings'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = ChangePasswordForm()

    if request.method == 'POST':
        try:
            current_user.username = request.form.get('username', current_user.username)
            current_user.about_me = request.form.get('about_me', current_user.about_me)
            current_user.show_links = 'show_links' in request.form
            current_user.dark_mode = 'dark_mode' in request.form

            if 'cropped_avatar' in request.form and request.form['cropped_avatar']:
                try:
                    cropped_data = request.form['cropped_avatar'].split(',')[1]
                    image_data = base64.b64decode(cropped_data)
                    filename = f"user_{current_user.id}_{int(datetime.now().timestamp())}.jpg"
                    avatar_path = os.path.join(app.config['AVATAR_UPLOAD_FOLDER'], filename)

                    if not os.path.exists(app.config['AVATAR_UPLOAD_FOLDER']):
                        os.makedirs(app.config['AVATAR_UPLOAD_FOLDER'])

                    with open(avatar_path, 'wb') as f:
                        f.write(image_data)

                    if current_user.avatar != 'default.jpg':
                        old_avatar = os.path.join(app.config['AVATAR_UPLOAD_FOLDER'], current_user.avatar)
                        if os.path.exists(old_avatar):
                            os.remove(old_avatar)

                    current_user.avatar = filename
                except Exception as e:
                    logger.error(f'Avatar processing error: {str(e)}')
                    flash('Ошибка обработки аватара', 'error')

            db.session.commit()
            flash('Настройки успешно обновлены!', 'success')
            return redirect(url_for('settings'))

        except Exception as e:
            db.session.rollback()
            logger.error(f'Settings save error: {str(e)}')
            flash(f'Ошибка при сохранении: {str(e)}', 'danger')

    return render_template('settings.html',
                           user=current_user,
                           form=form)


@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author_id != current_user.id:
        return jsonify({'success': False}), 403

    try:
        Like.query.filter_by(post_id=post.id).delete()
        Comment.query.filter_by(post_id=post.id).delete()
        db.session.delete(post)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f'Ошибка удаления поста: {str(e)}')
        return jsonify({'success': False}), 500


# Обновленный эндпоинт для закладок
@app.route('/api/bookmark_post/<int:post_id>', methods=['POST'])
@login_required
def api_bookmark_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        is_bookmarked = current_user.toggle_bookmark(post)
        db.session.commit()

        return jsonify({
            'success': True,
            'is_bookmarked': is_bookmarked
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/like_post/<int:post_id>', methods=['POST'])
@login_required
def api_like_post(post_id):
    try:
        # Проверка CSRF токена
        validate_csrf(request.headers.get('X-CSRFToken'))

        post = Post.query.get_or_404(post_id)
        existing_like = Like.query.filter_by(
            user_id=current_user.id,
            post_id=post.id
        ).first()

        if existing_like:
            db.session.delete(existing_like)
            action = 'unliked'
        else:
            new_like = Like(user_id=current_user.id, post_id=post.id)
            db.session.add(new_like)
            action = 'liked'

        db.session.commit()

        return jsonify({
            'success': True,
            'action': action,
            'likes_count': post.likes.count(),
            'is_liked': not existing_like
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Эндпоинт для закладок
@app.route('/bookmark/<int:post_id>', methods=['POST'])
@login_required
def bookmark_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post in current_user.bookmarked_posts:
        current_user.bookmarked_posts.remove(post)
        is_bookmarked = False
    else:
        current_user.bookmarked_posts.append(post)
        is_bookmarked = True

    db.session.commit()

    return jsonify({
        'success': True,
        'is_bookmarked': is_bookmarked
    })


@app.route('/bookmarks')
@login_required
def get_bookmarks():
    try:
        bookmarked_posts = current_user.bookmarked_posts.all()
        return jsonify([{
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'author': {
                'id': post.author.id,
                'username': post.author.username,
                'avatar': post.author.avatar
            }
        } for post in bookmarked_posts])
    except Exception as e:
        logger.error(f'Ошибка получения закладок: {str(e)}')
        return jsonify({'success': False}), 500


@app.route('/account')
@login_required
def account():
    user = current_user
    page = request.args.get('page', 1, type=int)

    # Получаем посты с пагинацией
    posts = user.posts.order_by(Post.created_at.desc()).paginate(
        page=page,
        per_page=10,
        error_out=False
    )

    # Обновляем счетчики
    user.update_counters()

    return render_template(
        'account.html',
        user=user,
        posts=posts,
        title=f"Профиль {user.username}"
    )


@app.route('/subscriptions')
@login_required
def subscriptions():
    subscriptions = current_user.following.all()
    return render_template('subscriptions.html',
                           subscriptions=subscriptions)


@app.route('/api/add_comment/<int:post_id>', methods=['POST'])
@login_required
def api_add_comment(post_id):
    try:
        # Проверка CSRF токена
        validate_csrf(request.headers.get('X-CSRFToken'))

        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data provided'}), 400

        content = data.get('content', '').strip()
        if not content:
            return jsonify({'success': False, 'error': 'Comment cannot be empty'}), 400

        post = Post.query.get_or_404(post_id)
        comment = Comment(
            content=content,
            post_id=post.id,
            user_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()

        return jsonify({
            'success': True,
            'comment': comment.to_dict(),
            'comments_count': post.comments.count()
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding comment: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/delete_comment/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    try:
        comment = Comment.query.get_or_404(comment_id)
        post = comment.post

        # Проверяем права на удаление
        if comment.user_id != current_user.id and post.author_id != current_user.id:
            return jsonify({
                'success': False,
                'error': 'Недостаточно прав для удаления'
            }), 403

        db.session.delete(comment)

        # Обновляем счетчики
        if post.author.total_comments > 0:
            post.author.total_comments -= 1

        db.session.commit()

        return jsonify({
            'success': True,
            'comments_count': post.comments_count,
            'total_comments': post.author.total_comments
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f'Ошибка при удалении комментария: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/get_comments/<int:post_id>')
def get_comments(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        paginated_comments = post.comments.order_by(Comment.created_at.desc()).paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        comments = [{
            'id': c.id,
            'content': c.content,
            'created_at': c.created_at.strftime('%d.%m.%Y %H:%M'),
            'user': {
                'id': c.user.id,
                'username': c.user.username,
                'avatar': c.user.avatar
            },
            'can_delete': c.user_id == current_user.id or post.author_id == current_user.id
        } for c in paginated_comments.items]

        return jsonify({
            'success': True,
            'comments': comments,
            'has_more': paginated_comments.has_next,
            'total_comments': post.comments_count
        })

    except Exception as e:
        logger.error(f'Ошибка при получении комментариев: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/search')
@login_required
def search():
    try:
        query = request.args.get('query', '').strip()

        if not query:
            # Получаем историю из исправленной связи
            search_history = current_user.search_history_entries.order_by(
                SearchHistory.timestamp.desc()
            ).limit(10).all()

            return render_template('search.html',
                                   query='',
                                   users=[],
                                   posts=[],
                                   search_history=search_history
                                   )

        # Сохраняем запрос с обработкой ошибок
        try:
            existing = SearchHistory.query.filter_by(
                user_id=current_user.id,
                search_query=query
            ).first()

            if existing:
                existing.timestamp = datetime.utcnow()
            else:
                new_entry = SearchHistory(
                    user_id=current_user.id,
                    search_query=query
                )
                db.session.add(new_entry)
            db.session.commit()
        except Exception as e:
            app.logger.error(f"Ошибка сохранения истории: {str(e)}")
            db.session.rollback()

        # Улучшенный поиск с учетом регистра
        search_pattern = f"%{query}%"

        users = User.query.filter(
            User.username.ilike(search_pattern)
        ).all()

        posts = Post.query.filter(
            Post.content.ilike(search_pattern)
        ).options(joinedload(Post.author)).order_by(Post.created_at.desc()).all()

        return render_template('search.html',
                               query=query,
                               users=users,
                               posts=posts,
                               search_history=[]
                               )

    except Exception as e:
        app.logger.error(f"Search error: {str(e)}", exc_info=True)
        return render_template('search.html',
                               query=query,
                               users=[],
                               posts=[],
                               search_history=[]
                               )


@app.route('/notifications')
@login_required
def notifications():
    notifications = current_user.notifications.order_by(
        Notification.created_at.desc()).all()
    return render_template('notifications.html',
                           notifications=notifications)


@app.route('/toggle_dark_mode', methods=['POST'])
@login_required
def toggle_dark_mode():
    if not current_user.is_authenticated:
        return jsonify({'success': False}), 401

    try:
        current_user.dark_mode = not current_user.dark_mode
        db.session.commit()
        return jsonify({
            'success': True,
            'dark_mode': current_user.dark_mode
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f'Dark mode toggle error: {str(e)}')
        return jsonify({'success': False}), 500


# Мессенджер
@app.route('/messenger')
@login_required
def messenger():
    chats = Chat.query.filter(
        or_(
            Chat.user1_id == current_user.id,
            Chat.user2_id == current_user.id
        )
    ).order_by(Chat.last_message_at.desc()).all()

    conversations = []
    for chat in chats:
        other_user = chat.get_other_user(current_user.id)
        last_message = chat.messages.order_by(Message.sent_at.desc()).first()
        unread_count = chat.messages.filter(
            Message.sender_id != current_user.id,
            Message.is_read == False
        ).count()

        conversations.append({
            'user': other_user,
            'chat': chat,
            'last_message': last_message.to_dict() if last_message else None,
            'unread_count': unread_count
        })

    return render_template('messenger.html',
                           conversations=conversations)


@app.route('/chat/<int:chat_id>')
@login_required
def view_chat(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if current_user.id not in [chat.user1_id, chat.user2_id]:
        abort(403)

    recipient = chat.get_other_user(current_user.id)
    messages = chat.messages.order_by(Message.sent_at.asc()).all()

    chat.messages.filter(
        Message.sender_id == recipient.id,
        Message.is_read == False
    ).update({'is_read': True})
    db.session.commit()

    return render_template('chat.html',
                           chat=chat,
                           recipient=recipient,
                           messages=messages)


@app.route('/api/messages/<int:chat_id>')
@login_required
def get_messages_api(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if current_user.id not in [chat.user1_id, chat.user2_id]:
        return jsonify({'error': 'Доступ запрещен'}), 403

    messages = chat.messages.order_by(Message.sent_at.asc()).all()
    return jsonify([m.to_dict() for m in messages])


@app.route('/api/send_message', methods=['POST'])
@login_required
def api_send_message():
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        content = data.get('content', '').strip()

        if not recipient_id or not content:
            return jsonify({'status': 'error', 'message': 'Invalid data'}), 400

        recipient = User.query.get(recipient_id)
        if not recipient:
            return jsonify({'status': 'error', 'message': 'Recipient not found'}), 404

        chat = Chat.query.filter(
            or_(
                and_(Chat.user1_id == current_user.id, Chat.user2_id == recipient_id),
                and_(Chat.user1_id == recipient_id, Chat.user2_id == current_user.id)
            )
        ).first()

        if not chat:
            chat = Chat(user1_id=current_user.id, user2_id=recipient_id)
            db.session.add(chat)
            db.session.commit()

        message = Message(
            chat_id=chat.id,
            sender_id=current_user.id,
            content=content
        )
        chat.update_last_message_time()
        db.session.add(message)
        db.session.commit()

        socketio.emit('new_message', {
            'chat_id': chat.id,
            'message': message.to_dict(),
            'recipient_id': recipient_id
        }, room=f'user_{recipient_id}')

        return jsonify({
            'status': 'success',
            'message': message.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# WebSocket обработчики
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        current_user.is_online = True
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()
        emit('user_status', {
            'user_id': current_user.id,
            'status': 'online',
            'last_seen': current_user.last_seen.isoformat()
        }, broadcast=True)


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.is_online = False
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()
        emit('user_status', {
            'user_id': current_user.id,
            'status': 'offline',
            'last_seen': current_user.last_seen.isoformat()
        }, broadcast=True)


@socketio.on('typing')
def handle_typing(data):
    chat_id = data.get('chat_id')
    if not chat_id:
        return

    chat = Chat.query.get(chat_id)
    if not chat or current_user.id not in [chat.user1_id, chat.user2_id]:
        return

    recipient_id = chat.user1_id if chat.user2_id == current_user.id else chat.user2_id
    emit('typing', {
        'chat_id': chat_id,
        'user_id': current_user.id
    }, room=f'user_{recipient_id}')


@socketio.on('stop_typing')
def handle_stop_typing(data):
    chat_id = data.get('chat_id')
    if not chat_id:
        return

    chat = Chat.query.get(chat_id)
    if not chat or current_user.id not in [chat.user1_id, chat.user2_id]:
        return

    recipient_id = chat.user1_id if chat.user2_id == current_user.id else chat.user2_id
    emit('stop_typing', {
        'chat_id': chat_id,
        'user_id': current_user.id
    }, room=f'user_{recipient_id}')


@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data.get('chat_id')
    if chat_id:
        join_room(f'chat_{chat_id}')


@app.route('/toggle_subscription/<int:user_id>', methods=['POST'])
@login_required
def toggle_subscription(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if current_user.is_following(user):
            current_user.unfollow(user)
            action = 'unfollowed'
        else:
            current_user.follow(user)
            action = 'followed'

        db.session.commit()
        return jsonify({
            'success': True,
            'action': action,
            'followers_count': user.followers.count()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f'Subscription error: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/delete_search_history/<history_id>', methods=['POST'])
def delete_search_history(history_id):
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    history_item = SearchHistory.query.get(history_id)
    if not history_item or history_item.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Item not found'}), 404

    db.session.delete(history_item)
    db.session.commit()
    return jsonify({'success': True})

# Запуск приложения
def create_app():
    with app.app_context():
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['AVATAR_UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['MESSAGE_UPLOAD_FOLDER'], exist_ok=True)
        db.create_all()


if __name__ == '__main__':
    create_app()
    socketio.run(app, debug=True)