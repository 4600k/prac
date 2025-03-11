import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Email, Length
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.orm import relationship
import uuid
from google.cloud import storage
from dotenv import load_dotenv
from sqlalchemy import inspect

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysecretkey123')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+pg8000://postgres:qwerty123321@localhost:5432/photo_album'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    folders = relationship('Folder', backref='user', lazy=True)
    photos = relationship('Photo', backref='user', lazy=True)

class Folder(db.Model):
    __tablename__ = 'folder'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent = relationship('Folder', remote_side=[id], backref='subfolders')

class Photo(db.Model):
    __tablename__ = 'photo'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    folder = relationship('Folder', backref='photos')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Увійти')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Зареєструватися')

class UploadForm(FlaskForm):
    photo = FileField('Фото', validators=[DataRequired()])
    folder = SelectField('Папка', coerce=int, choices=[(0, 'Без папки')], default=0)
    submit = SubmitField('Завантажити')

class CreateFolderForm(FlaskForm):
    name = StringField('Назва папки', validators=[DataRequired()])
    parent = SelectField('Батьківська папка', coerce=int, choices=[(0, 'Без папки')], default=0)
    submit = SubmitField('Створити')

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'service-account-key.json'
storage_client = storage.Client()
bucket_name = '1my-photo-bucket'
bucket = storage_client.bucket(bucket_name)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Користувач із таким email уже існує!', 'danger')
            return render_template('register.html', form=form)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Реєстрація успішна! Тепер ви можете увійти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Ви успішно увійшли!', 'success')
            return redirect(url_for('album'))
        else:
            flash('Невірний email або пароль.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли з системи.', 'success')
    return redirect(url_for('index'))

@app.route('/album')
@login_required
def album():
    folders = Folder.query.filter_by(user_id=current_user.id, parent_id=None).all()
    photos = Photo.query.filter_by(user_id=current_user.id, folder_id=None).all()
    
    for photo in photos:
        blob = bucket.get_blob(photo.filename)
        if blob:
            signed_url = blob.generate_signed_url(expiration=datetime.timedelta(minutes=15))
            print(f"Signed URL for {photo.filename}: {signed_url}")  
            photo.signed_url = signed_url
        else:
            print(f"Blob not found for {photo.filename}")  
            photo.signed_url = photo.url 
    return render_template('album.html', folders=folders, photos=photos)

@app.route('/folder/<int:folder_id>')
@login_required
def folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    if folder.user_id != current_user.id:
        flash('У вас немає доступу до цієї папки.', 'danger')
        return redirect(url_for('album'))
    subfolders = Folder.query.filter_by(parent_id=folder.id).all()
    photos = Photo.query.filter_by(folder_id=folder.id).all()
    
    for photo in photos:
        blob = bucket.get_blob(photo.filename)
        if blob:
            signed_url = blob.generate_signed_url(expiration=datetime.timedelta(minutes=15))
            print(f"Signed URL for {photo.filename}: {signed_url}")  
            photo.signed_url = signed_url
        else:
            print(f"Blob not found for {photo.filename}")  
            photo.signed_url = photo.url  
    return render_template('folder.html', folder=folder, subfolders=subfolders, photos=photos)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    folders = [(0, 'Без папки')] + [(f.id, f.name) for f in Folder.query.filter_by(user_id=current_user.id).all()]
    form = UploadForm()
    form.folder.choices = folders
    if form.validate_on_submit():
        try:
            file = form.photo.data
            filename = f"{uuid.uuid4()}_{file.filename}"
            blob = bucket.blob(filename)
            blob.upload_from_file(file, content_type=file.content_type)  
            url = blob.public_url
            folder_id = form.folder.data if form.folder.data != 0 else None
            new_photo = Photo(filename=filename, url=url, user_id=current_user.id, folder_id=folder_id)
            db.session.add(new_photo)
            db.session.commit()
            flash('Фото успішно завантажено!', 'success')
            return redirect(url_for('album'))
        except Exception as e:
            flash(f'Помилка при завантаженні фото: {str(e)}', 'danger')
    return render_template('upload.html', form=form)

@app.route('/create_folder', methods=['GET', 'POST'])
@login_required
def create_folder():
    folders = [(0, 'Без папки')] + [(f.id, f.name) for f in Folder.query.filter_by(user_id=current_user.id).all()]
    form = CreateFolderForm()
    form.parent.choices = folders
    if form.validate_on_submit():
        name = form.name.data
        parent_id = form.parent.data if form.parent.data != 0 else None
        new_folder = Folder(name=name, user_id=current_user.id, parent_id=parent_id)
        db.session.add(new_folder)
        db.session.commit()
        flash('Папку успішно створено!', 'success')
        return redirect(url_for('album'))
    return render_template('create_folder.html', form=form)

def init_db():
    with app.app_context():
        inspector = inspect(db.engine)
        tables_exist = (
            inspector.has_table('user') and
            inspector.has_table('folder') and
            inspector.has_table('photo')
        )
        photo_columns = [col['name'] for col in inspector.get_columns('photo')] if inspector.has_table('photo') else []
        expected_photo_columns = {'id', 'filename', 'url', 'folder_id', 'user_id'}
        if not tables_exist or set(photo_columns) != expected_photo_columns:
            print("Структура бази даних не відповідає моделям, перестворюємо таблиці...")
            db.drop_all()
            db.create_all()
            print("Таблиці створено з актуальною структурою.")
        else:
            print("Таблиці вже існують і відповідають моделям.")


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
