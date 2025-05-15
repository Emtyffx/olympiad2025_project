import os
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory, flash, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import logging
import bcrypt
from sqlalchemy import func
import uuid
from sqlalchemy.pool import NullPool
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Налаштування логування
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Створюємо новий додаток Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'секретный_ключ'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///newflask.db?timeout=30'
app.config['UPLOAD_FOLDER'] = 'upload'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'poolclass': NullPool}
app.permanent_session_lifetime = timedelta(minutes=10)  # Тайм-аут сесії 10 хвилин
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)

# Налаштування для відправки email через Gmail SMTP
EMAIL_ADDRESS = ''
EMAIL_PASSWORD = ''
SMTP_SERVER = ''
SMTP_PORT = 587

# Custom UserMixin for multiple user types
class CustomUser(UserMixin):
    def __init__(self, user=None, teacher=None, admin=None):
        self.user = user
        self.teacher = teacher
        self.admin = admin

    def get_id(self):
        if self.user:
            return f"user_{self.user.id}"
        elif self.teacher:
            return f"teacher_{self.teacher.id}"
        elif self.admin:
            return f"admin_{self.admin.id}"
        return None

    @property
    def role(self):
        if self.user:
            return self.user.role
        elif self.teacher:
            return "teacher"
        elif self.admin:
            return "admin"
        return None

    @property
    def is_authenticated(self):
        return bool(self.user or self.teacher or self.admin)

# Модель користувача (clas змінено на String, оскільки ми використовуємо "Юний біолог" тощо)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(150), unique=True)
    name = db.Column(db.String(150))
    surname = db.Column(db.String(150))
    tel = db.Column(db.String(150))
    clas = db.Column(db.String(50))  # Змінено з Integer на String
    password = db.Column(db.String(150))
    role = db.Column(db.String(50))

# Модель для сесій входу
class LoginSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    phone = db.Column(db.String(150), nullable=True)
    browser = db.Column(db.String(255), nullable=False)
    session_code = db.Column(db.String(255), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)  # Додано для відстеження активності

# Інші моделі
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    class_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Завантаження користувача
@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith("user_"):
        user = db.session.get(User, int(user_id.replace("user_", "")))
        return CustomUser(user=user) if user else None
    elif user_id.startswith("teacher_"):
        teacher = db.session.get(Teacher, int(user_id.replace("teacher_", "")))
        return CustomUser(teacher=teacher) if teacher else None
    elif user_id.startswith("admin_"):
        admin = db.session.get(Admin, int(user_id.replace("admin_", "")))
        return CustomUser(admin=admin) if admin else None
    return None

# Функція для перевірки валідної сесії (перевірка 10 хвилин бездіяльності)
def has_valid_session():
    if 'session_code' not in session:
        return False
    session_code = session['session_code']
    login_session = LoginSession.query.filter_by(session_code=session_code).first()
    if not login_session:
        return False
    # Перевірка терміну дії (10 хвилин бездіяльності)
    time_threshold = datetime.utcnow() - timedelta(minutes=10)
    browser = request.headers.get('User-Agent', 'Unknown')
    if (login_session.last_activity >= time_threshold and
            login_session.browser == browser and
            current_user.is_authenticated):
        # Оновлюємо час останньої активності
        login_session.last_activity = datetime.utcnow()
        db.session.commit()
        return True
    return False

# Глобальна перевірка сесії перед кожним запитом
@app.before_request
def check_session():
    if request.path in ['/login', '/register', '/logout', '/static/<path:filename>']:  # Виключення для логін/реєстрація/статичних файлів
        return
    if current_user.is_authenticated and not has_valid_session():
        logout_user()
        session.pop('session_code', None)
        logger.info("Сесія завершена через бездіяльність")
        return redirect(url_for('login'))

# Реєстрація
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form['login']
        name = request.form['name']
        surname = request.form['surname']
        tel = request.form['tel']
        clas = request.form['clas']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        role = request.form['role']

        # Валідація clas
        allowed_classes = ["Юний біолог", "Хореографічний", "Комп'ютерний"]
        if clas not in allowed_classes:
            logger.warning(f"Невірний клас при реєстрації: {clas}")
            return jsonify({'error': f'Невірний клас: {clas}. Допустимі значення: {allowed_classes}'}), 400

        if password != password_confirm:
            logger.warning(f"Спроба реєстрації з невідповідними паролями: login={login}")
            return jsonify({'error': 'Паролі не співпадають'}), 400

        if User.query.filter_by(login=login).first():
            logger.warning(f"Спроба реєстрації з існуючим логіном: {login}")
            return jsonify({'error': 'Такий користувач вже існує'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = User(login=login, name=name, surname=surname, tel=tel, clas=clas, password=hashed_password, role=role)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(CustomUser(user=new_user))
            session.permanent = True  # Увімкнути перманентну сесію
            session_code = str(uuid.uuid4())
            browser = request.headers.get('User-Agent', 'Unknown')
            new_session = LoginSession(
                user_id=new_user.id,
                phone=new_user.tel,
                browser=browser,
                session_code=session_code,
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow()
            )
            db.session.add(new_session)
            db.session.commit()
            session['session_code'] = session_code
            logger.info(f"Користувач зареєстрований: login={login}, role={role}, session_code={session_code}")
            return jsonify({
                'message': 'Реєстрація успішна!',
                'login': login,
                'redirect': url_for('index')
            }), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Помилка при реєстрації: {str(e)}")
            return jsonify({'error': f'Помилка при реєстрації: {str(e)}'}), 500
    return render_template('calendar.html')

# Авторизація
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            if request.is_json:
                data = request.get_json()
                login = data.get('login')
                password = data.get('password')
            else:
                login = request.form.get('login')
                password = request.form.get('password')
        except Exception as e:
            logger.error(f"Помилка при розпарсюванні даних: {str(e)}")
            return jsonify({'error': 'Невалідні дані у запиті'}), 400

        if not login or not password:
            logger.warning(f"Некоректні дані для авторизації: login={login}")
            return jsonify({'error': 'Відсутній email/логін або пароль'}), 400

        # Check User table
        user = User.query.filter_by(login=login).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(CustomUser(user=user))
            session.permanent = True
            session_code = str(uuid.uuid4())
            browser = request.headers.get('User-Agent', 'Unknown')
            new_session = LoginSession(
                user_id=user.id,
                phone=user.tel,
                browser=browser,
                session_code=session_code,
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow()
            )
            try:
                db.session.add(new_session)
                db.session.commit()
                session['session_code'] = session_code
                logger.info(f"Сесія створена: user_id={user.id}, phone={user.tel}, browser={browser}")
                return jsonify({
                    'message': 'Авторизація успішна!',
                    'redirect': url_for('home')  # Змінено на 'home'
                }), 200
            except Exception as e:
                db.session.rollback()
                logger.error(f"Помилка при створенні сесії: {str(e)}")
                return jsonify({'error': f'Помилка при створенні сесії: {str(e)}'}), 500

        # Check Teacher table
        teacher = Teacher.query.filter_by(email=login).first()
        if teacher and bcrypt.checkpw(password.encode('utf-8'), teacher.password.encode('utf-8')):
            login_user(CustomUser(teacher=teacher))
            session.permanent = True
            session_code = str(uuid.uuid4())
            browser = request.headers.get('User-Agent', 'Unknown')
            new_session = LoginSession(
                user_id=None,
                phone=None,
                browser=browser,
                session_code=session_code,
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow()
            )
            try:
                db.session.add(new_session)
                db.session.commit()
                session['session_code'] = session_code
                logger.info(f"Сесія створена: teacher_id={teacher.id}, email={teacher.email}, browser={browser}")
                return jsonify({
                    'message': 'Авторизація успішна!',
                    'redirect': url_for('home')  # Змінено на 'home'
                }), 200
            except Exception as e:
                db.session.rollback()
                logger.error(f"Помилка при створенні сесії: {str(e)}")
                return jsonify({'error': f'Помилка при створенні сесії: {str(e)}'}), 500

        # Check Admin table
        admin = Admin.query.filter_by(email=login).first()
        if admin and bcrypt.checkpw(password.encode('utf-8'), admin.password.encode('utf-8')):
            login_user(CustomUser(admin=admin))
            session.permanent = True
            session_code = str(uuid.uuid4())
            browser = request.headers.get('User-Agent', 'Unknown')
            new_session = LoginSession(
                user_id=None,
                phone=None,
                browser=browser,
                session_code=session_code,
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow()
            )
            try:
                db.session.add(new_session)
                db.session.commit()
                session['session_code'] = session_code
                logger.info(f"Сесія створена: admin_id={admin.id}, email={admin.email}, browser={browser}")
                return jsonify({
                    'message': 'Авторизація успішна!',
                    'redirect': url_for('home')  # Змінено на 'home'
                }), 200
            except Exception as e:
                db.session.rollback()
                logger.error(f"Помилка при створенні сесії: {str(e)}")
                return jsonify({'error': f'Помилка при створенні сесії: {str(e)}'}), 500

        logger.warning(f"Невдала спроба авторизації: login={login}")
        return jsonify({'error': 'Невірний email або пароль'}), 401
    return render_template('Index.html')

# Вихід
@app.route('/logout')
def logout():
    if 'session_code' in session:
        login_session = LoginSession.query.filter_by(session_code=session['session_code']).first()
        if login_session:
            db.session.delete(login_session)
            db.session.commit()
            logger.info(f"Сесія видалена: session_code={session['session_code']}")
        session.pop('session_code', None)
    logout_user()
    return redirect(url_for('index'))

# Головна сторінка
@app.route('/')
def index():
    is_authenticated = has_valid_session()
    user = current_user if is_authenticated and current_user.is_authenticated else None
    return render_template('Index.html', is_authenticated=is_authenticated, user=user)

# Оновлений маршрут home для ролей
@app.route('/home')
def home():
    if not has_valid_session():
        return redirect(url_for('index'))  # Перенаправлення на головну сторінку

    user_role = current_user.role
    if user_role == 'admin':
        return render_template('admin.html')
    elif user_role == 'teacher':
        return render_template('teacher.html')
    elif user_role == 'student':
        return render_template('student.html', user=current_user.user)
    elif user_role == 'parent':
        return render_template('parents.html', user=current_user.user, students=User.query.filter(
            func.trim(func.lower(User.clas)) == func.trim(func.lower(current_user.user.clas)),
            User.role == 'student'
        ).all())
    else:
        return redirect(url_for('index'))

# Захищений маршрут для профілю
@app.route('/profile')
@login_required
def profile():
    if not has_valid_session():
        return redirect(url_for('index'))
    user_role = current_user.role
    if user_role == 'admin':
        return render_template('admin_profile.html', user=current_user.admin)
    elif user_role == 'teacher':
        return render_template('teacher_profile.html', user=current_user.teacher)
    elif user_role in ['student', 'parent']:
        return render_template('profile.html', user=current_user.user)  # Змінено на profile.html
    else:
        return redirect(url_for('index'))

# Захищений маршрут для вчителя
@app.route("/teacher")
def teacher():
    if not has_valid_session() or current_user.role != 'teacher':
        return redirect(url_for('index'))
    return render_template('teacher.html')

# Захищений маршрут для батьків
@app.route("/parents")
def parent():
    if not has_valid_session() or current_user.role != 'parent':
        logger.warning(f"Невірна роль або сесія для доступу до /parents: role={current_user.role if current_user else None}, session_valid={has_valid_session()}")
        return redirect(url_for('index'))

    parent_user = current_user.user if current_user.is_authenticated else None
    students = []
    if parent_user:
        parent_clas = parent_user.clas
        if not parent_clas:
            logger.error(f"Parent user has no clas: login={parent_user.login}")
            return redirect(url_for('index'))

        # Логування значення clas для перевірки
        logger.info(f"Parent accessing /parents: login={parent_user.login}, clas='{parent_clas}' (raw: {repr(parent_clas)})")

        # Запит із видаленням пробілів і порівнянням у нижньому регістрі
        students = User.query.filter(
            func.trim(func.lower(User.clas)) == func.trim(func.lower(parent_clas)),
            User.role == 'student'
        ).all()

        logger.info(f"Found {len(students)} students with clas '{parent_clas}'")
        for student in students:
            logger.info(f"Student: id={student.id}, login={student.login}, name={student.name}, surname={student.surname}, clas='{student.clas}' (raw: {repr(student.clas)})")
        if not students:
            logger.warning(f"No students found for clas '{parent_clas}'")
            # Додатковий запит для перевірки всіх учнів
            all_students = User.query.filter(User.role == 'student').all()
            logger.info(f"All students in database: {[(s.id, s.login, s.clas, repr(s.clas)) for s in all_students]}")
    else:
        logger.warning("No parent_user found for /parents route")

    return render_template('parents.html', user=parent_user, students=students)

# Захищений маршрут для студента
@app.route("/student")
def student():
    if not has_valid_session() or current_user.role != 'student':
        return redirect(url_for('index'))
    return render_template('student.html', user=current_user if current_user.is_authenticated else None)

@app.route("/calendar")
def calendar():
    return render_template('calendar.html')

# Захищений маршрут для адміна
@app.route("/admin")
def admin():
    if not has_valid_session() or current_user.role != 'admin':
        return redirect(url_for('index'))
    try:
        return render_template('admin.html')
    except Exception as e:
        logger.error(f"Помилка рендерингу admin.html: {str(e)}")
        return str(e), 500

@app.route("/api/events", methods=['GET'])
def get_events():
    events = Event.query.all()
    return jsonify([{
        'id': event.id,
        'title': event.title,
        'date': event.date.strftime('%Y-%m-%d %H:%M:%S')
    } for event in events])

@app.route("/api/events", methods=['POST'])
def create_event():
    data = request.json
    if not data or 'title' not in data or 'date' not in data:
        return jsonify({'error': 'Некоректні дані'}), 400
    try:
        # Спробуємо спочатку парсити з секундами
        try:
            event_date = datetime.strptime(data['date'], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # Якщо формат без секунд, додаємо :00
            event_date = datetime.strptime(data['date'] + ':00', '%Y-%m-%d %H:%M:%S')

        event = Event(
            title=data['title'],
            date=event_date
        )
        db.session.add(event)
        db.session.commit()
        logger.info(f"Створено подію: ID={event.id}, Назва={event.title}, Дата={event.date}")
        return jsonify({
            'id': event.id,
            'title': event.title,
            'date': event.date.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Помилка при створенні події: {str(e)}")
        return jsonify({'error': 'Помилка при створенні події'}), 500

@app.route("/api/events/<int:id>", methods=['PUT'])
def update_event(id):
    event = Event.query.get_or_404(id)
    data = request.json
    if not data or 'title' not in data or 'date' not in data:
        return jsonify({'error': 'Некоректні дані'}), 400
    try:
        # Спробуємо спочатку парсити з секундами
        try:
            event_date = datetime.strptime(data['date'], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # Якщо формат без секунд, додаємо :00
            event_date = datetime.strptime(data['date'] + ':00', '%Y-%m-%d %H:%M:%S')

        event.title = data['title']
        event.date = event_date
        db.session.commit()
        logger.info(f"Оновлено подію: ID={event.id}, Назва={event.title}, Дата={event.date}")
        return jsonify({
            'id': event.id,
            'title': event.title,
            'date': event.date.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Помилка при оновленні події ID={id}: {str(e)}")
        return jsonify({'error': 'Помилка при оновленні події'}), 500

@app.route("/api/events/<int:event_id>", methods=['DELETE'])
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    try:
        logger.info(f"Видаляємо подію: ID={event.id}, Назва={event.title}, Дата={event.date}")
        db.session.delete(event)
        db.session.commit()
        logger.info(f"Подію успішно видалено: ID={event_id}")
        return '', 204
    except Exception as e:
        db.session.rollback()
        logger.error(f"Помилка при видаленні події ID={event_id}: {str(e)}")
        return jsonify({'error': 'Помилка при видаленні події'}), 500

# Функція для відправки email
def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        server.quit()
        logger.info(f"Email надіслано на {to_email}")
        return True
    except Exception as e:
        logger.error(f"Помилка при відправці email на {to_email}: {str(e)}")
        return False

# Маршрут для розсилки повідомлень
@app.route('/api/messages/send', methods=['POST'])
def send_message():
    logger.info("Початок розсилки...")
    try:
        if not current_user.is_authenticated or current_user.role != 'admin':
            logger.warning("Недостатньо прав для розсилки повідомлень")
            return jsonify({'error': 'Недостатньо прав'}), 403

        data = request.json
        if not data or 'message' not in data or 'recipient' not in data:
            logger.error(f"Некоректні дані для розсилки: {data}")
            return jsonify({'error': 'Некоректні дані: відсутнє поле message або recipient'}), 400

        message = data['message']
        recipient = data['recipient']

        roles = []
        if recipient == 'students':
            roles = ['student']
        elif recipient == 'parents':
            roles = ['parent']
        elif recipient == 'all':
            roles = ['student', 'parent']
        else:
            logger.error(f"Некоректний тип отримувача: {recipient}")
            return jsonify({'error': 'Некоректний тип отримувача'}), 400

        users = User.query.filter(User.role.in_(roles)).all()

        sent_count = 0
        failed_count = 0

        for user in users:
            if not user.login:
                logger.warning(f"Користувач без email: ID={user.id}, Ім'я={user.name}")
                failed_count += 1
                continue

            subject = "Повідомлення від адміністратора"
            body = f"Шановний(а) {user.name} {user.surname},\n\n{message}\n\nЗ повагою,\nАдміністрація"
            if send_email(user.login, subject, body):
                sent_count += 1
            else:
                failed_count += 1

        logger.info(f"Розсилка успішно завершена: надіслано {sent_count}, не надіслано {failed_count}")
        return jsonify({'sent': sent_count, 'failed': failed_count, 'status': 'Розсилка завершена'}), 200

    except Exception as e:
        logger.error(f"Помилка при розсилці повідомлень: {str(e)}")
        return jsonify({'error': 'Помилка при розсилці повідомлень'}), 500

# Маршрути для вчителів
@app.route('/api/teachers', methods=['GET'])
def get_teachers():
    logger.info("Отримано запит на отримання списку вчителів")
    try:
        teachers = Teacher.query.all()
        teachers_list = [{
            'id': teacher.id,
            'firstName': teacher.first_name,
            'lastName': teacher.last_name,
            'role': 'Вчитель'
        } for teacher in teachers]
        logger.info(f"Знайдено вчителів: {len(teachers_list)}")
        return jsonify(teachers_list), 200
    except Exception as e:
        logger.error(f"Помилка при отриманні списку вчителів: {str(e)}")
        return jsonify({'error': 'Помилка при отриманні списку вчителів'}), 500

@app.route('/api/teachers', methods=['POST'])
def add_teacher():
    logger.info(f"Отримано запит: headers={request.headers}")
    logger.info(f"Тіло запиту: {request.get_data(as_text=True)}")
    
    try:
        data = request.json
    except Exception as e:
        logger.error(f"Помилка при розпарсюванні JSON: {str(e)}")
        return jsonify({'error': 'Невалідний JSON у запиті'}), 400
    
    logger.info(f"Розпарсені JSON-дані: {data}")
    
    if not data:
        logger.error("Дані відсутні (data is None)")
        return jsonify({'error': 'Некоректні дані: дані відсутні'}), 400
    
    required_fields = ['email', 'firstName', 'lastName', 'class', 'password']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        logger.error(f"Відсутні обов’язкові поля: {missing_fields}")
        return jsonify({'error': f'Некоректні дані: відсутні поля {missing_fields}'}), 400

    email = data['email'].strip()
    first_name = data['firstName'].strip()
    last_name = data['lastName'].strip()
    class_name = data['class'].strip()
    password = data['password'].strip()

    allowed_classes = ["Комп'ютерний", "Юний біолог", "Хореографічний"]
    if class_name not in allowed_classes:
        logger.error(f"Невірний клас: {class_name}")
        return jsonify({'error': f'Невірний клас: {class_name}. Допустимі значення: {allowed_classes}'}), 400

    try:
        if Teacher.query.filter_by(email=email).first() or Admin.query.filter_by(email=email).first():
            logger.warning(f"Email уже зайнятий: {email}")
            return jsonify({'error': 'Email уже зайнятий'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        teacher = Teacher(
            email=email,
            first_name=first_name,
            last_name=last_name,
            class_name=class_name,
            password=hashed_password
        )
        db.session.add(teacher)
        db.session.commit()
        logger.info(f"Створено вчителя: ID={teacher.id}, Email={teacher.email}, Ім'я={teacher.first_name}, Прізвище={teacher.last_name}, Клас={teacher.class_name}")
        return jsonify({
            'id': teacher.id,
            'email': teacher.email,
            'firstName': teacher.first_name,
            'lastName': teacher.last_name,
            'class': teacher.class_name
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Помилка при створенні вчителя: {str(e)}")
        return jsonify({'error': 'Помилка при створенні вчителя'}), 500

@app.route('/api/teachers/search', methods=['POST'])
def search_teacher():
    logger.info(f"Отримано запит на пошук вчителя: headers={request.headers}")
    logger.info(f"Тіло запиту: {request.get_data(as_text=True)}")

    try:
        data = request.json
    except Exception as e:
        logger.error(f"Помилка при розпарсюванні JSON: {str(e)}")
        return jsonify({'error': 'Невалідний JSON у запиті'}), 400

    logger.info(f"Розпарсені JSON-дані: {data}")

    if not data or 'firstName' not in data or 'lastName' not in data:
        logger.error(f"Некоректні дані для пошуку вчителя: {data}")
        return jsonify({'error': 'Некоректні дані: відсутні поля firstName або lastName'}), 400

    first_name = data['firstName'].strip()
    last_name = data['lastName'].strip()

    try:
        teacher = Teacher.query.filter(
            func.lower(Teacher.first_name) == func.lower(first_name),
            func.lower(Teacher.last_name) == func.lower(last_name)
        ).first()
        
        if teacher:
            logger.info(f"Вчитель знайдений: Ім'я={teacher.first_name}, Прізвище={teacher.last_name}")
            return jsonify({
                'found': True,
                'id': teacher.id,
                'suggestions': []
            }), 200
        else:
            logger.info(f"Вчитель не знайдений: Ім'я={first_name}, Прізвище={last_name}")
            suggestions = Teacher.query.filter(
                (func.lower(Teacher.first_name).like(f'%{first_name.lower()}%')) |
                (func.lower(Teacher.last_name).like(f'%{last_name.lower()}%'))
            ).all()
            
            suggestions_list = [
                {'firstName': t.first_name, 'lastName': t.last_name}
                for t in suggestions
            ]
            logger.info(f"Знайдено схожих вчителів: {suggestions_list}")
            
            return jsonify({
                'found': False,
                'suggestions': suggestions_list
            }), 204
    except Exception as e:
        logger.error(f"Помилка при пошуку вчителя: {str(e)}")
        return jsonify({'error': 'Помилка при пошуку вчителя'}), 500

@app.route('/api/teachers/delete', methods=['DELETE'])
def delete_teacher():
    logger.info(f"Отримано запит на видалення вчителя: headers={request.headers}")
    logger.info(f"Тіло запиту: {request.get_data(as_text=True)}")

    try:
        data = request.json
    except Exception as e:
        logger.error(f"Помилка при розпарсюванні JSON: {str(e)}")
        return jsonify({'error': 'Невалідний JSON у запиті'}), 400

    logger.info(f"Розпарсені JSON-дані: {data}")

    if not data or 'firstName' not in data or 'lastName' not in data:
        logger.error(f"Некоректні дані для видалення вчителя: {data}")
        return jsonify({'error': 'Некоректні дані: відсутні поля firstName або lastName'}), 400

    first_name = data['firstName'].strip()
    last_name = data['lastName'].strip()

    try:
        teacher = Teacher.query.filter(
            func.lower(Teacher.first_name) == func.lower(first_name),
            func.lower(Teacher.last_name) == func.lower(last_name)
        ).first()
        if not teacher:
            logger.warning(f"Вчитель не знайдений для видалення: Ім'я={first_name}, Прізвище={last_name}")
            return jsonify({'error': 'Вчитель не знайдений'}), 404

        logger.info(f"Видаляємо вчителя: ID={teacher.id}, Ім'я={teacher.first_name}, Прізвище={teacher.last_name}")
        db.session.delete(teacher)
        db.session.commit()
        logger.info(f"Вчитель успішно видалений: Ім'я={first_name}, Прізвище={last_name}")
        return '', 204
    except Exception as e:
        db.session.rollback()
        logger.error(f"Помилка при видаленні вчителя: {str(e)}")
        return jsonify({'error': 'Помилка при видаленні вчителя'}), 500

# Маршрути для адміністраторів
@app.route('/api/admins', methods=['GET'])
def get_admins():
    logger.info("Отримано запит на отримання списку адміністраторів")
    try:
        admins = Admin.query.all()
        admins_list = [{
            'id': admin.id,
            'firstName': admin.first_name,
            'lastName': admin.last_name,
            'role': 'Адміністратор'
        } for admin in admins]
        logger.info(f"Знайдено адміністраторів: {len(admins_list)}")
        return jsonify(admins_list), 200
    except Exception as e:
        logger.error(f"Помилка при отриманні списку адміністраторів: {str(e)}")
        return jsonify({'error': 'Помилка при отриманні списку адміністраторів'}), 500

@app.route('/api/admins', methods=['POST'])
def add_admin():
    logger.info(f"Отримано запит на додавання адміністратора: headers={request.headers}")
    logger.info(f"Тіло запиту: {request.get_data(as_text=True)}")
    
    try:
        data = request.json
    except Exception as e:
        logger.error(f"Помилка при розпарсюванні JSON: {str(e)}")
        return jsonify({'error': 'Невалідний JSON у запиті'}), 400
    
    logger.info(f"Розпарсені JSON-дані: {data}")
    
    if not data:
        logger.error("Дані відсутні (data is None)")
        return jsonify({'error': 'Некоректні дані: дані відсутні'}), 400
    
    required_fields = ['email', 'firstName', 'lastName', 'password']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        logger.error(f"Відсутні обов’язкові поля: {missing_fields}")
        return jsonify({'error': f'Некоректні дані: відсутні поля {missing_fields}'}), 400

    email = data['email'].strip()
    first_name = data['firstName'].strip()
    last_name = data['lastName'].strip()
    password = data['password'].strip()

    try:
        if Teacher.query.filter_by(email=email).first() or Admin.query.filter_by(email=email).first():
            logger.warning(f"Email уже зайнятий: {email}")
            return jsonify({'error': 'Email уже зайнятий'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        admin = Admin(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=hashed_password
        )
        db.session.add(admin)
        db.session.commit()
        logger.info(f"Створено адміністратора: ID={admin.id}, Email={admin.email}, Ім'я={admin.first_name}, Прізвище={admin.last_name}")
        return jsonify({
            'id': admin.id,
            'email': admin.email,
            'firstName': admin.first_name,
            'lastName': admin.last_name
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Помилка при створенні адміністратора: {str(e)}")
        return jsonify({'error': 'Помилка при створенні адміністратора'}), 500

@app.route('/api/admins/search', methods=['POST'])
def search_admin():
    logger.info(f"Отримано запит на пошук адміністратора: headers={request.headers}")
    logger.info(f"Тіло запиту: {request.get_data(as_text=True)}")

    try:
        data = request.json
    except Exception as e:
        logger.error(f"Помилка при розпарсюванні JSON: {str(e)}")
        return jsonify({'error': 'Невалідний JSON у запиті'}), 400

    logger.info(f"Розпарсені JSON-дані: {data}")

    if not data or 'firstName' not in data or 'lastName' not in data:
        logger.error(f"Некоректні дані для пошуку адміністратора: {data}")
        return jsonify({'error': 'Некоректні дані: відсутні поля firstName або lastName'}), 400

    first_name = data['firstName'].strip()
    last_name = data['lastName'].strip()

    try:
        admin = Admin.query.filter(
            func.lower(Admin.first_name) == func.lower(first_name),
            func.lower(Admin.last_name) == func.lower(last_name)
        ).first()
        
        if admin:
            logger.info(f"Адміністратор знайдений: Ім'я={admin.first_name}, Прізвище={admin.last_name}")
            return jsonify({
                'found': True,
                'id': admin.id,
                'suggestions': []
            }), 200
        else:
            logger.info(f"Адміністратор не знайдений: Ім'я={first_name}, Прізвище={last_name}")
            suggestions = Admin.query.filter(
                (func.lower(Admin.first_name).like(f'%{first_name.lower()}%')) |
                (func.lower(Admin.last_name).like(f'%{last_name.lower()}%'))
            ).all()
            
            suggestions_list = [
                {'firstName': a.first_name, 'lastName': a.last_name}
                for a in suggestions
            ]
            logger.info(f"Знайдено схожих адміністраторів: {suggestions_list}")
            
            return jsonify({
                'found': False,
                'suggestions': suggestions_list
            }), 404
    except Exception as e:
        logger.error(f"Помилка при пошуку адміністратора: {str(e)}")
        return jsonify({'error': 'Помилка при пошуку адміністратора'}), 500

@app.route('/api/admins/delete', methods=['DELETE'])
def delete_admin():
    logger.info(f"Отримано запит на видалення адміністратора: headers={request.headers}")
    logger.info(f"Тіло запиту: {request.get_data(as_text=True)}")

    try:
        data = request.json
    except Exception as e:
        logger.error(f"Помилка при розпарсюванні JSON: {str(e)}")
        return jsonify({'error': 'Невалідний JSON у запиті'}), 400

    logger.info(f"Розпарсені JSON-дані: {data}")

    if not data or 'firstName' not in data or 'lastName' not in data:
        logger.error(f"Некоректні дані для видалення адміністратора: {data}")
        return jsonify({'error': 'Некоректні дані: відсутні поля firstName або lastName'}), 400

    first_name = data['firstName'].strip()
    last_name = data['lastName'].strip()

    try:
        admin = Admin.query.filter(
            func.lower(Admin.first_name) == func.lower(first_name),
            func.lower(Admin.last_name) == func.lower(last_name)
        ).first()
        if not admin:
            logger.warning(f"Адміністратор не знайдений для видалення: Ім'я={first_name}, Прізвище={last_name}")
            return jsonify({'error': 'Адміністратор не знайдений'}), 404

        logger.info(f"Видаляємо адміністратора: ID={admin.id}, Ім'я={admin.first_name}, Прізвище={admin.last_name}")
        db.session.delete(admin)
        db.session.commit()
        logger.info(f"Адміністратор успішно видалений: Ім'я={first_name}, Прізвище={last_name}")
        return '', 204
    except Exception as e:
        db.session.rollback()
        logger.error(f"Помилка при видаленні адміністратора: {str(e)}")
        return jsonify({'error': 'Помилка при видаленні адміністратора'}), 500

@app.route('/api/students', methods=['GET'])
def get_students():
    logger.info("Отримано запит на отримання списку учнів")
    try:
        if not current_user.is_authenticated or current_user.role != 'teacher':
            logger.warning("Недостатньо прав для доступу до списку учнів")
            return jsonify({'error': 'Недостатньо прав'}), 403

        teacher = current_user.teacher
        class_name = teacher.class_name

        students = User.query.filter(
            User.clas == class_name,
            User.role == 'student'
        ).all()

        students_list = [{
            'id': student.id,
            'name': student.name,
            'surname': student.surname,
            'login': student.login
        } for student in students]

        logger.info(f"Знайдено учнів: {len(students_list)} для класу {class_name}")
        return jsonify({
            'class_name': class_name,
            'students': students_list
        }), 200
    except Exception as e:
        logger.error(f"Помилка при отриманні списку учнів: {str(e)}")
        return jsonify({'error': 'Помилка при отриманні списку учнів'}), 500

@app.route('/api/students/delete', methods=['DELETE'])
def delete_students():
    logger.info(f"Отримано запит на видалення учнів: headers={request.headers}")
    logger.info(f"Тіло запиту: {request.get_data(as_text=True)}")

    try:
        if not current_user.is_authenticated or current_user.role != 'teacher':
            logger.warning("Недостатньо прав для видалення учнів")
            return jsonify({'error': 'Недостатньо прав'}), 403

        data = request.json
        if not data or 'student_ids' not in data:
            logger.error(f"Некоректні дані для видалення учнів: {data}")
            return jsonify({'error': 'Некоректні дані: відсутнє поле student_ids'}), 400

        student_ids = data['student_ids']
        if not isinstance(student_ids, list):
            logger.error(f"Некоректний формат student_ids: {student_ids}")
            return jsonify({'error': 'student_ids має бути списком'}), 400

        teacher = current_user.teacher
        class_name = teacher.class_name

        # Перевіряємо, що учні належать до класу вчителя
        students = User.query.filter(
            User.id.in_(student_ids),
            User.clas == class_name,
            User.role == 'student'
        ).all()

        if len(students) != len(student_ids):
            logger.warning(f"Деякі учні не знайдені або не належать до класу вчителя: {student_ids}")
            return jsonify({'error': 'Деякі учні не знайдені або не належать до вашого класу'}), 404

        for student in students:
            logger.info(f"Видаляємо учня: ID={student.id}, Ім'я={student.name}, Прізвище={student.surname}")
            db.session.delete(student)

        db.session.commit()
        logger.info(f"Учні успішно видалені: {student_ids}")
        return '', 204
    except Exception as e:
        db.session.rollback()
        logger.error(f"Помилка при видаленні учнів: {str(e)}")
        return jsonify({'error': 'Помилка при видаленні учнів'}), 500
    
@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/file", methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file')
            return redirect(request.url)
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_file = File(
                file_name=filename
            )
            db.session.add(new_file)
            db.session.commit()
    return '''
        <!doctype html>
        <title>Upload new File</title>
        <h1>Upload new File</h1>
        <form method=post enctype=multipart/form-data>
          <input type=file name=file>
          <input type=submit value=Upload>
        </form>
    '''
@app.route('/profile_student/<int:user_id>')
def profile_student(user_id):
    student = User.query.get_or_404(user_id)
    return render_template('student_profile.html', student=student)

@app.route('/file/download/<int:id>')
def download_file(id):
    file = File.query.get_or_404(id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.file_name)

@app.route('/users')
def list_users():
    users = User.query.all()
    return '<br>'.join([f'ID: {user.id}, Name: {user.name}, Role: {user.role}' for user in users])

# Обробник 404 помилки
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        logger.info("База даних ініціалізована")
    app.run(host="0.0.0.0", port=5000, debug=True)
