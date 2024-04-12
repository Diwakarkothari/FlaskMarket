
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, Email, EqualTo, DataRequired, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SECRET_KEY'] = '4d5f8a7df1923ea04893ef45'

# to run manually
# set FLASK_APP=market.py
# set FLASK_DEBUG = 1
# flask run

# after imports
# from market import db,app,Item
# in terminal write
# app.app_context().push()
# db.create_all()
# so it will work without error
# be sure to use that command


# for item in Item.query.all():
# ...    item.name
# use indentation
# ...
# display
# to filter data from database
# for item in Item.query.filter_by(rate=1234):
# ...    item.name
# all the name will be displayed

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"  # login hone ke baad message aayega uski category


class LoginForm(FlaskForm):
    username = StringField(label='User name', validators=[DataRequired()])
    password = PasswordField(label='password:', validators=[Length(min=6), DataRequired()])
    submit = SubmitField(label='Log in')


class RegisterForm(FlaskForm):

    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exist')

    def validate_email_address(self, email_to_check):
        email_addr = User.query.filter_by(email_address=email_to_check.data).first()
        if email_addr:
            raise ValidationError('Email already exist')

    username = StringField(label='User Name:', validators=[Length(min=2, max=30), DataRequired()])
    email_address = StringField(label='Email Address', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='confirm password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create account')


@login_manager.user_loader  # login manager ko use karne ke liye define karna padega
def load_user(user_id):
    return User.query.get(int(user_id))


class PurchaseItemForm(FlaskForm):
    submit = SubmitField(label='Purchase Item!')


class SellItemForm(FlaskForm):
    submit = SubmitField(label='Sell Item!')


# kuch aur functions bhi override karne padenge , updated by UserMixin
class User(db.Model, UserMixin):    # user naam ki table ban jayegi database mein
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    budget = db.Column(db.Integer(), nullable=False, default=1000)
    items = db.relationship('Item', backref='owned_user', lazy=True)

    @property
    def password(self):   # getter
        return self.password

    @password.setter
    def password(self, plain_text_password):   # setter
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self, attempted_password):   # password correct or not checking
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

    def can_purchase(self, item_obj):
        return self.budget >= item_obj.price

    def can_sell(self, item_obj):
        return item_obj in self.items


class Item(db.Model):   # creation of a table name Item in database
    product_id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=30), nullable=False, unique=True)
    price = db.Column(db.Integer(), nullable=False)
    barcode = db.Column(db.String(length=12), nullable=False, unique=True)
    description = db.Column(db.String(length=1024), nullable=False, unique=True)
    owner = db.Column(db.Integer(), db.ForeignKey('user.id'))

    def __repr__(self):
        return f'Item {self.name}'

    def buy(self, user):
        self.owner = user.id
        user.budget -= self.price
        db.session.commit()

    def sell(self, user):
        self.owner = None
        user.budget += self.price
        db.session.commit()


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/market', methods=['GET', 'POST'])
@login_required
def market():
    purchase_form = PurchaseItemForm()
    selling_form = SellItemForm()
    if request.method == "POST":
        purchased_item = request.form.get('purchased_item')
        p_item_object = Item.query.filter_by(name=purchased_item).first()
        if p_item_object:
            if current_user.can_purchase(p_item_object):
                p_item_object.buy(current_user)
                flash(f'Purchase of {p_item_object.name} at price of {p_item_object.price}$ successful',
                      category='success')
            else:
                flash(f"Unfortunately you don't have enough budget to purchase {p_item_object.name}",
                      category='danger')

        sold_item = request.form.get('sold_item')
        s_item_object = Item.query.filter_by(name=sold_item).first()
        if s_item_object:
            if current_user.can_sell(s_item_object):
                s_item_object.sell(current_user)
                flash(f'Selling of {s_item_object.name} at price of {s_item_object.price}$ successful',
                      category='success')
            else:
                flash(f"Unfortunately you don't ownership of {s_item_object.name} so you can't sell it",
                      category='danger')

        return redirect(url_for('market'))

    if request.method == "GET":
        z = Item.query.filter_by(owner=None)
        owned_items = Item.query.filter_by(owner=current_user.id)
        return render_template('market.html', items=z, purchase_form=purchase_form, owned_items=owned_items,
                               selling_form=selling_form)


@app.route('/register', methods=['GET', 'POST'])  # methods aage register.html mein use hoga
def register():
    form1 = RegisterForm()
    if form1.validate_on_submit():
        user_to_create = User(username=form1.username.data,   # ignore warnings UserMixin ki wajah se aayi hai
                              email_address=form1.email_address.data,
                              password=form1.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)  # jis se register kara uss he se login hoga immediately
        flash(f'Account created successfully ! You are now logged in as {user_to_create.username}', category='success')
        return redirect(url_for('market'))
    if form1.errors != {}:  # empty dictionary
        # if there are errors
        for err_msg in form1.errors.values():
            flash(f'Error creating an user : {err_msg}', category='danger')
    # wrong details stay on register page
    return render_template('register.html', form=form1)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form2 = LoginForm()
    if form2.validate_on_submit():
        user_to_check = User.query.filter_by(username=form2.username.data).first()
        if user_to_check and user_to_check.check_password_correction(attempted_password=form2.password.data):
            login_user(user_to_check)  # username and password both correct , you are now logged in
            flash('Success!', category='success')
            return redirect(url_for('market'))
        else:
            flash('Email and password does not match   Please try again', category='danger')

    return render_template('login.html', form=form2)


@app.route('/logout')
def logout():
    logout_user()  # ye logout kar dega no more code required
    flash('You have been logged out!', category='info')  # message dikha dega
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
