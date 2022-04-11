from email.mime import base
from enum import unique
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask import Flask, request, Response
from werkzeug.utils import secure_filename
from sqlalchemy.orm import relationship
import base64

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'comp3334-group-project'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    arts = relationship("Art", backref="user")
    # taskid = db.relationship('Task', backref='user')
    # TODO

# TODO


class Art(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, unique=True)
    img = db.Column(db.Text, nullable=False, unique=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner_id = db.Column(db.Integer)
    creationdate = db.Column(db.DateTime, nullable=False, default=datetime.now)
    mimetype = db.Column(db.Text, nullable=False)

# class Task(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     ownerid = db.Column(db.Integer, db.ForeignKey('user.id'))
#     name = db.Column(db.String(20), nullable=False)
#     completion = db.Column(db.Boolean)
#     desc = db.Column(db.String(400), nullable=True)
#     creationdate = db.Column(db.DateTime, nullable=False,
#                              default=datetime.now)
#     # id, ownerid, name, completion, description, creation date


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


@app.route('/')
def index():

    images = Art.query.all()

    if not images:
        return render_template('index.html')

    return_images = []
    art_data = []

    for image in images:
        base64_image = base64.b64encode(image.img)
        return_images.append(base64_image.decode("UTF-8"))
        art_data.append(image)

    return render_template('index.html', images=return_images, art_data=art_data, length=len(art_data))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    msg = ""

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('main'))
            else:
                msg = "Username / Password is incorrect."
                return render_template('login.html', form=form, msg=msg)
        else:
            msg = "Username / Password is incorrect."
            return render_template('login.html', form=form, msg=msg)

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect((url_for('login')))

    return render_template('register.html', form=form)


@app.route('/main')
@login_required
def main():

    user = User.query.filter_by(username=current_user.username).first()
    # task_list = Task.query.filter_by(ownerid=user.id)

    images = user.arts
    return_images = []

    for image in images:
        base64_image = base64.b64encode(image.img)
        return_images.append(base64_image.decode("UTF-8"))

    return render_template('main.html', user=user, images=return_images)


@app.route('/main/upload', methods=['POST'])
@login_required
def upload():
    picname = request.form.get('picname')
    pic = request.files['pic']
    if not pic:
        return 'Not Picture!', 400

    filename = secure_filename(pic.filename)
    mimetype = pic.mimetype
    if not filename or not mimetype:
        return 'Bad upload!', 400

    art = Art(img=pic.read(), name=picname, mimetype=mimetype,
              creator_id=current_user.id, owner_id=current_user.id)
    db.session.add(art)
    db.session.commit()

    return redirect((url_for('main')))


if __name__ == '__main__':

    db.create_all()

    app.run(debug=True)
