from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return True

    def get_id(self):
        return str(self.id)


with app.app_context():
    db.create_all()

login_manager.login_view = "login"

logged_in = None


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/')
def home():
    return render_template("index.html", logged_in=logged_in)


@app.route('/register', methods=['POST', 'GET'])
def register():
    error = None
    if request.method == 'POST':
        salt = generate_password_hash(request.form.get("password"), 'pbkdf2', 8)
        new_user = User(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=salt
        )
        result = db.session.execute(db.select(User).where(User.email == request.form.get("email")))
        if result:
            error = "Email already exists. Please Login"

            return redirect(url_for('login', error=error))
        else:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("secrets"))
    return render_template("register.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    error = request.args.get("error")
    if error is None:
        error = None
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        result = db.session.execute(db.select(User).where(User.email == email))
        if result:
            user = result.scalar()
            if check_password_hash(user.password, password):
                login_user(user)
                global logged_in
                logged_in = True
                return redirect(url_for('secrets'))
            else:
                error = "Invalid Login"
        else:
            error = "Email not found."
    return render_template("login.html", error=error)


@app.route('/secrets')
@login_required
def secrets():
    name = current_user.name
    value = request.args.get("value", type=bool)
    return render_template("secrets.html", name=name, logged_in=value)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    global logged_in
    logged_in = False
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(
            'static', "files/cheat_sheet.pdf", as_attachment=True
        )


if __name__ == "__main__":
    app.run(debug=True)
