from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,validators, ValidationError
from wtforms.validators import InputRequired, Email
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta
import email_validator
 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_cle_secrete'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Utilisation de SQLite pour la simplicité
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'arafmia56@gmail.com'
app.config['MAIL_USERNAME'] = 'arafmia56@gmail.com'
app.config['MAIL_PASSWORD'] = 'rsmp udfd seks jaeq'

mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp_code = db.Column(db.String(8), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    action = db.Column(db.String(50), nullable=False)
    last_activity_time = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(15), nullable=True)
    browser_info = db.Column(db.String(255), nullable=True)
    cookies_info = db.Column(db.String(255), nullable=True)
    usage_data = db.Column(db.Text, nullable=True)
    approximate_location = db.Column(db.String(50), nullable=True)
    device_info = db.Column(db.String(255), nullable=True)
    operating_system = db.Column(db.String(50), nullable=True)


class ConnectionAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False)
    ip_address = db.Column(db.String(15), nullable=True)
    browser_info = db.Column(db.String(255), nullable=True)
    operating_system = db.Column(db.String(50), nullable=True)
    device_info = db.Column(db.String(255), nullable=True)
    location_info = db.Column(db.String(50), nullable=True)

class VisitorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    action = db.Column(db.String(50), nullable=False)
    last_activity_time = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(15), nullable=True)
    browser_info = db.Column(db.String(255), nullable=True)
    cookies_info = db.Column(db.String(255), nullable=True)
    usage_data = db.Column(db.Text, nullable=True)
    approximate_location = db.Column(db.String(50), nullable=True)
    device_info = db.Column(db.String(255), nullable=True)
    operating_system = db.Column(db.String(50), nullable=True)

 

class SignupForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[InputRequired()])
    confirm_password = PasswordField('Confirmer le mot de passe', validators=[
        InputRequired(),
        validators.EqualTo('password', message='Les mots de passe doivent correspondre')
    ])
    submit = SubmitField('S\'inscrire')

class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[InputRequired()])
    password = PasswordField('Mot de passe', validators=[InputRequired()])
    submit = SubmitField('Se connecter')

class OTPForm(FlaskForm):
    otp = StringField('Code OTP', validators=[InputRequired()])
    submit = SubmitField('Valider')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        # Vérifiez si l'utilisateur existe déjà dans la base de données
        existing_user = User.query.filter_by(username=form.username.data).first()
        collect_visitor_info('signup')

        if existing_user:
            flash('Cet utilisateur existe déjà. Veuillez choisir un autre nom d\'utilisateur.', 'danger')
            return redirect(url_for('signup'))

        # Créez un nouvel utilisateur
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        )

        # Ajoutez le nouvel utilisateur à la base de données
        db.session.add(new_user)
        db.session.commit()

        flash('Compte créé avec succès. Veuillez vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

# ... le reste du code ...

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):
            otp_code = secrets.token_hex(4)
            send_otp_email(user.username, user.email, otp_code)
            session['otp_code'] = otp_code
            login_user(user)
            flash('Code OTP envoyé à votre adresse e-mail.', 'success')
            log_user_activity('Connexion réussie')
            collect_connection_info(user_id=user.id, success=True)
            collect_visitor_info('login')
            return redirect(url_for('otp'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
            collect_connection_info(user_id=None, success=False)

    return render_template('login.html', form=form)

@app.route('/otp', methods=['GET', 'POST'])
@login_required
def otp():
    form = OTPForm()

    if form.validate_on_submit():
        entered_otp = form.otp.data
        stored_otp = session.get('otp_code')

        if stored_otp and entered_otp == stored_otp:
            flash('Code OTP correct. Connexion réussie!', 'success')
            # Vous pouvez effectuer des actions supplémentaires ici si nécessaire
            return redirect(url_for('dashboard'))
        else:
            flash('Code OTP incorrect. Veuillez réessayer.', 'danger')

    return render_template('otp.html', form=form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/cctv')
@login_required
def cctv():
    return render_template('cctv.html')

@app.route('/map')
@login_required
def map():
    return render_template('map.html')

@app.route('/rapport')
@login_required
def rapport():
    return render_template('rapport.html')

@app.route('/setting')
@login_required
def setting():
    return render_template('setting.html')

@app.route('/analytic')
@login_required
def analytic():
    return render_template('analytic.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté.', 'info')
    collect_visitor_info('logout')
    return redirect(url_for('login'))
    #... le reste du code ...

def send_otp_email(username, email, otp_code):
    subject = 'Code OTP de connexion'
    body = f'Bonjour {username},\nVotre code OTP est : {otp_code}\nCe code est à usage unique.'
    
    try:
        msg = Message(subject, recipients=[email], body=body)
        mail.send(msg)
        flash('Code OTP envoyé à votre adresse e-mail.', 'success')
    except Exception as e:
        flash(f'Erreur lors de l\'envoi du code OTP : {str(e)}', 'danger')


def log_user_activity(action, usage_data=None):
    """
    Enregistre l'activité de l'utilisateur dans la table ActivityLog.
    :param action: L'action réalisée par l'utilisateur.
    :param usage_data: Données d'utilisation supplémentaires (optionnel).
    """
    if current_user.is_authenticated:
        # Si l'utilisateur est authentifié, enregistrez l'activité dans la table ActivityLog
        activity_log = ActivityLog(
            user_id=current_user.id,
            action=action,
            ip_address=request.remote_addr,
            browser_info=request.user_agent.browser,
            cookies_info=str(request.cookies),
            usage_data=usage_data,
            approximate_location=request.headers.get('X-Real-IP'),  # Vous pouvez ajuster cela en fonction de votre configuration
            device_info=request.user_agent.string,
            operating_system=request.user_agent.platform,
        )

        db.session.add(activity_log)
        db.session.commit()

def collect_connection_info(user_id, success=True):
    # Collecte des informations de connexion
    ip_address = request.remote_addr
    browser_info = request.user_agent.browser
    operating_system = request.user_agent.platform
    device_info = request.user_agent.string

    # Enregistrement des informations dans la base de données
    connection_attempt = ConnectionAttempt(
        user_id=user_id,
        timestamp=datetime.utcnow(),
        success=success,
        ip_address=ip_address,
        browser_info=browser_info,
        operating_system=operating_system,
        device_info=device_info,
        location_info=None  # Vous pouvez remplir cette information en utilisant un service tiers
    )

    db.session.add(connection_attempt)
    db.session.commit()


def collect_visitor_info(action):
    # Collecte des informations du visiteur
    ip_address = request.remote_addr
    browser_info = request.user_agent.browser
    operating_system = request.user_agent.platform
    device_info = request.user_agent.string

    # Vous pouvez utiliser un service tiers pour obtenir une localisation approximative
    # basée sur l'adresse IP, par exemple, en utilisant une API de géolocalisation.

    # Enregistrement des informations dans la base de données
    visitor_log = VisitorLog(
        action=action,
        timestamp=datetime.utcnow(),
        ip_address=ip_address,
        browser_info=browser_info,
        operating_system=operating_system,
        device_info=device_info,
        last_activity_time=None,  # Vous pouvez remplir cette information si nécessaire
        cookies_info=None,  # Vous pouvez remplir cette information si nécessaire
        usage_data=None,  # Vous pouvez remplir cette information si nécessaire
        approximate_location=None  # Vous pouvez remplir cette information en utilisant un service tiers
    )

    db.session.add(visitor_log)
    db.session.commit()
# Crée les tables de la base de données si elles n'existent pas encore
with app.app_context():
    db.create_all()

# ... le reste du code ...

if __name__ == '__main__':
    app.run(debug=True)