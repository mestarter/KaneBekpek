import os
from flask import Flask, request, flash, url_for, redirect, render_template, Blueprint, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, logout_user, current_user, login_user
from wtforms import Form, StringField, PasswordField, validators, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length, Optional
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///backpack.sqlite3'
app.config['SECRET_KEY'] = "IDontCare"
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)


def create_app():
   app = Flask(__name__, instance_relative_config=False)

   app.config.from_object('config.Config')

   db.init_app(app)
   login_manager.init_app(app)

   with app.app_context():
      from . import routes
      from . import login
      app.register_blueprint(routes.main_bp)
      app.register_blueprint(login.login_bp)

      db.create_all()

      return app


class User(UserMixin, db.Model):
   id = db.Column(db.Integer, primary_key=True)
   username = db.Column(db.String,  nullable=False, unique=False)
   password = db.Column(db.String(225), primary_key=False, unique=False, nullable=False)

   def set_password(self, password):
      self.password = generate_password_hash(password, method='sha256')
   
   def check_password(self, password):
      print('checking')
      print(self.password)
      print(User.query.get(password))
      return check_password_hash(self.password, password) 

   def __repr__(self):
      return '<User {}>'.format(self.username)


class LoginForm(Form):

   username = StringField('Username', [DataRequired()])
   password = PasswordField('Password', [DataRequired()])
   submit = SubmitField('Log In')


class Consumables(db.Model):
   id = db.Column('id', db.Integer, primary_key = True)
   name = db.Column(db.String(100))
   amount = db.Column(db.Integer)

   def __init__(self, name, amount):
      self.name = name
      self.amount = amount


User.query.delete()
user = User(username='Admin', password=generate_password_hash('password', method='sha256'))
db.session.add(user)
db.session.commit()


db.create_all()


@app.route("/", methods=['GET', 'POST'])
def home():
   return render_template('home.html', consumables = Consumables.query.all(), form=LoginForm(), title='Log in | Flask-Login Tutorial.', template='login-page', body="Log in with your User account.")


@app.route('/login', methods=['GET', 'POST'])
def login_page():
      login_form = LoginForm(request.form)
      print(login_form.password)
      if request.method == 'POST':
         if login_form.validate():
               print('validated')
               username = request.form.get('username')
               password = request.form.get('password')
               user = User.query.filter_by(username=username).first()
               if user:
                  print('is user')
                  print(password)
                  print(user.check_password(password))
                  if user.check_password(password=password):
                     print('right password')
                     login_user(user)
                     flash('Logged in')
                     return redirect(url_for('home'))
         flash('Invalid username/password combination')
         return redirect(url_for('home'))

      return render_template('login.html', form=LoginForm(), title='Log in | Flask-Login Tutorial.', template='login-page', body="Log in with your User account.")


@app.route("/logout")
@login_required
def logout_page():
   logout_user()
   return redirect(url_for('home'))


@login_manager.user_loader
def load_user(user_id):
   if user_id is not None:
      return User.query.get(user_id)
   return None


@app.route('/new', methods = ['GET', 'POST'])
def new():
   if request.method == 'POST':
      if not request.form['name'] or not request.form['amount']:
         flash('Please enter all the fields', 'error')
      else:
         name = Consumables(request.form['name'], request.form['amount'])
         db.session.add(name)
         db.session.commit()
         
         flash('Item was successfully added')
         return redirect(url_for('home'))
      return redirect(url_for('home'))


@app.route('/delete', methods=['GET', 'POST'])
def delete():
   id_delete = int(request.form["id"])
   name = Consumables.query.filter_by(id=id_delete).first()
   db.session.delete(name)
   db.session.commit()
   return (redirect(url_for('home')))


if __name__ == "__main__":
   app.run(debug=True, port=8080)