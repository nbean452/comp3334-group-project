from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask import Flask, request
from werkzeug.utils import secure_filename
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


users_owned_arts = db.Table('user_owned_arts',
                            db.Column('user_id', db.Integer,
                                      db.ForeignKey('user.id')),
                            db.Column('art.id', db.Integer, db.ForeignKey('art.id')))

users_created_arts = db.Table('user_created_arts',
                              db.Column('user_id', db.Integer,
                                        db.ForeignKey('user.id')),
                              db.Column('art.id', db.Integer, db.ForeignKey('art.id')))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    balance = db.Column(db.Integer)

    owned_arts = db.relationship(
        'Art', secondary=users_owned_arts, backref='owner')
    created_arts = db.relationship(
        'Art', secondary=users_created_arts, backref='creator')

    # owned_arts = db.relationship("Art", backref="owner")
    # created_arts = db.relationship("Art", backref="creator")


class Art(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    img = db.Column(db.Text, nullable=False, unique=True)
    creationdate = db.Column(db.DateTime, nullable=False,
                             default=datetime.now)
    mimetype = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, default=0)

    transactions = db.relationship("Transaction", backref='art')

    # transc = db.relationship(
    #     'Art', secondary=transactions, backref='transaction')

    # creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False,
                     default=datetime.now)
    art_id = db.Column(db.Integer, db.ForeignKey('art.id'))

    seller_id = db.Column(db.Integer)
    buyer_id = db.Column(db.Integer)

    price = db.Column(db.Integer, default=0, nullable=False)

    # users = db.relationship("User", backref='transactions', lazy='dynamic')


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


@ app.route('/')
def index():

    images = Art.query.all()

    if not images:
        return render_template('index-for-anonymous.html', length=0)

    return_images = []
    art_data = []

    for image in images:
        base64_image = base64.b64encode(image.img)
        return_images.append(base64_image.decode("UTF-8"))
        art_data.append(image)

    if current_user.is_authenticated:
        return render_template('index-for-user.html', images=return_images, art_data=art_data, length=len(art_data), current_user=current_user)

    return render_template('index-for-anonymous.html', images=return_images, art_data=art_data, length=len(art_data))


@ app.route('/login', methods=['GET', 'POST'])
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


@ app.route('/logout', methods=['GET', 'POST'])
@ login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    # below function is for development purposes!
    # generate_users()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,
                        password=hashed_password, balance=0)
        db.session.add(new_user)
        db.session.commit()
        return redirect((url_for('login')))

    return render_template('register.html', form=form)


@ app.route('/main')
@ login_required
def main():

    user = User.query.filter_by(username=current_user.username).first()
    # task_list = Task.query.filter_by(ownerid=user.id)

    user_arts_num = len(user.owned_arts)
    images = user.owned_arts
    return_images = []

    for image in images:
        base64_image = base64.b64encode(image.img)
        return_images.append(base64_image.decode("UTF-8"))

    return render_template('main.html', user=user, images=return_images, length=user_arts_num)


@ app.route('/buy/<int:art_id>')
@ login_required
def buy(art_id):

    art = Art.query.filter_by(id=art_id).first()

    # if not enough balance
    if current_user.balance < art.price:
        return "Not enough balance, please top-up!", 200

    # on every transaction, creator gets 5% commision
    commision = int(art.price * 0.05)
    net_amount = art.price - commision

    # current user loses money
    current_user.balance -= art.price

    # art owner gets 95% of the money which is the net amount
    art.owner[0].balance += net_amount

    # art creator gets 5% of the full price which is the comission
    art.creator[0].balance += commision

    new_transc = Transaction(
        art=art, seller_id=art.owner[0].id, buyer_id=current_user.id, price=art.price)

    # art.transactions.append(new_transc)

    # transfer ownership to current user!
    art.owner[0] = current_user

    db.session.add(new_transc)
    db.session.commit()
    return redirect(url_for('index'))


@ app.route('/edit-art/<int:art_id>', methods=['POST'])
@ login_required
def edit_art(art_id):
    picname = request.form.get('picname')
    price = request.form.get('price')

    art = Art.query.filter_by(id=art_id).first()
    art.name = picname
    art.price = price
    db.session.commit()

    return redirect(url_for('main'))


@ app.route('/main/upload', methods=['POST'])
@ login_required
def upload():
    pic = request.files['pic']
    if not pic:
        return 'Not Picture!', 400

    picname = request.form.get('picname')
    price = request.form.get('price')

    filename = secure_filename(pic.filename)
    mimetype = pic.mimetype
    if not filename or not mimetype:
        return 'Bad upload!', 400

    # art = Art(img=pic.read(), name=picname, mimetype=mimetype,
    #           creator_id=current_user.id, owner_id=current_user.id, price=price)

    art = Art(img=pic.read(), name=picname, mimetype=mimetype, price=price)
    db.session.add(art)
    user = User.query.filter_by(id=current_user.id).first()
    user.owned_arts.append(art)
    user.created_arts.append(art)

    db.session.commit()

    return redirect((url_for('main')))


@ app.route('/topup', methods=['POST'])
@ login_required
def topup():
    amount = int(request.form.get('topup-amount'))
    user = User.query.filter_by(id=current_user.id).first()
    user.balance += amount
    db.session.commit()
    return redirect(url_for('main'))


def generate_users():
    db.session.add(User(username='nicho', password=bcrypt.generate_password_hash(
        '123123'), balance=100))
    db.session.add(User(
        username='john', password=bcrypt.generate_password_hash('123123'), balance=100))
    db.session.add(User(username='steve', password=bcrypt.generate_password_hash(
        '123123'), balance=100))
    db.session.commit()


@ app.route('/art/<int:art_id>')
def transactions(art_id):
    art = Art.query.filter_by(id=art_id).first()

    base64_image = base64.b64encode(art.img)
    outer_array = []

    for transaction in art.transactions:
        inner_array = []
        user = User.query.filter_by(id=transaction.seller_id).first()
        inner_array.append(user)
        user = User.query.filter_by(id=transaction.buyer_id).first()
        inner_array.append(user)
        inner_array.append(transaction.price)
        inner_array.append(transaction.date)
        outer_array.append(inner_array)

    return render_template("art-details.html", image=base64_image.decode("UTF-8"), art_data=art, transaction_info=outer_array)


if __name__ == '__main__':

    db.create_all()

    app.run(debug=True)
