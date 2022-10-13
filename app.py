from dateutil import parser
# from crypt import *
from flask import Flask, render_template, session, request, redirect, url_for, flash, jsonify
from flask_restful import Api, Resource, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy, Model

from werkzeug.security import generate_password_hash, check_password_hash


from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user
from datetime import datetime

from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,Email,EqualTo



app                                     = Flask(__name__)
app.secret_key                          = "Devrev project"
app.config['TEMPLATES_AUTO_RELOAD']     = True

app.config['SQLALCHEMY_DATABASE_URI']   = 'sqlite:///db.sqlite'
db                                      = SQLAlchemy(app)

login_manager                           = LoginManager()
login_manager.init_app(app)

api                                     = Api(app)

#FUNCTIONS

def auth():
    return current_user.is_authenticated

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)




class RegistrationForm(FlaskForm):
    name = StringField('username',                  validators =[DataRequired()])
    email = StringField('Email',                    validators=[DataRequired(),Email()])
    password1 = PasswordField('Password',           validators = [DataRequired()])
    password2 = PasswordField('Confirm Password',   validators = [DataRequired(),EqualTo('password1')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email',                    validators=[DataRequired(), Email()])
    password = PasswordField('Password',            validators=[DataRequired()])
    remember = BooleanField('Remember Me',          default = False)
    submit = SubmitField('Login')


#DATABASE

class User(UserMixin, db.Model):
  id            = db.Column(db.Integer, primary_key=True)
  name          = db.Column(db.String(50))
  email         = db.Column(db.String(150), unique = True, index = True)
  password_hash = db.Column(db.String(150))
  joined_at     = db.Column(db.DateTime(), default = datetime.utcnow, index = True)

  def set_password(self, password):
        self.password_hash = generate_password_hash(password)

  def check_password(self,password):
      return check_password_hash(self.password_hash,password)

  @classmethod
  def get(self, id):
    return self.query.get(id)

class Flight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    from_ = db.Column(db.String(50))
    to_ = db.Column(db.String(50))
    date = db.Column(db.DateTime())
    time = db.Column(db.String(50))
    tickets = db.Column(db.Integer)
    price = db.Column(db.Integer)

    def _asdict(self):
        return {
            'id': self.id,
            'name': self.name,
            'from_': self.from_,
            'to_': self.to_,
            'date': str(self.date),
            'time': self.time,
            'price': self.price,
            'tickets': self.tickets,
            'date_' : self.date.strftime('%d-%b-%Y')
        }

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flight_id = db.Column(db.Integer, db.ForeignKey('flight.id'))
    tickets = db.Column(db.Integer)
    price = db.Column(db.Integer)
    user = db.Column(db.Integer, db.ForeignKey('user.id'))

    def _asdict(self):
        return {
            'id': self.id,
            'flight_id': self.flight_id,
            'tickets': self.tickets,
            'price' : self.price,
            'user' : self.user
        }

class CREATE_FLIGHT(Resource):  
    def put(self):
        args = request.get_json()
        date = parser.parse(args['date']).date()
        flight = Flight(name = args['name'], from_ = args['from'], to_ = args['to'], date = date, time = args['time'], price = args['price'], tickets = 60)
        db.session.add(flight)
        db.session.commit()
        print('commited successfully')
        return {"status": "success", "object": flight._asdict()}

class SEARCH_FLIGHT(Resource):
    def get(self):
        args = request.args
        if (args['date']!=""):
            date = parser.parse(args['date'])
        else:
            date = ""
        flights = Flight.query.all()
        if args['from'] != ' ':
            flights = list(map(lambda x: x, filter(lambda x: x.from_.lower().startswith(args['from'].lower()), flights)))
        if args['to'] != ' ':
            flights = list(map(lambda x: x, filter(lambda x: x.to_.lower().startswith(args['to'].lower()), flights)))
        if date != '':
            flights = list(map(lambda x: x, filter(lambda x: x.date == date, flights)))
        
        for idx in range(len(flights)):
            flights[idx] = flights[idx]._asdict()
        
        return jsonify(flights)

class REMOVE_FLIGHT_API(Resource):
    def post(self):
        args = request.get_json()
        flight = Flight.query.get(args['id'])
        db.session.delete(flight)
        db.session.commit()

        return {'message': 'Flight Deleted Successfully'}

class BOOK_FLIGHT(Resource):
    def put(self):
        args = request.get_json()
        ticket = Ticket(flight_id=args['id'],tickets=args['ticket'],price = args['price'], user = current_user.id)
        flight = Flight.query.get(args['id'])
        flight.tickets-=args['ticket']
        db.session.add(ticket)
        db.session.commit()

        return {'message': 'Flight Booked Successfully'}

    def get(self):
        id = current_user.id
        tickets = Ticket.query.filter_by(user=id).all()

        for idx in range(len(tickets)):
            tickets[idx] = tickets[idx]._asdict()
            flight_details = Flight.query.filter_by(id = tickets[idx]['flight_id']).first()
            if not flight_details:
                continue
            for detail in flight_details._asdict().keys():
                if detail in ['tickets', 'date', 'price']:
                    continue
                tickets[idx][detail] = flight_details._asdict()[detail]
        return jsonify(tickets)


 

# with app.app_context():
#     db.create_all()



@app.route('/register', methods = ['POST','GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(name =form.name.data, email = form.email.data)
        user.set_password(form.password1.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user, remember = form.remember.data)
            return redirect(url_for('index'))
        flash('Invalid email address or Password.')    
    return render_template('login.html', form=form)


@app.route('/admin_login', methods=['GET','POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user and user.check_password(form.password.data) and user.email == "admin@admin.com":
            login_user(user, remember = form.remember.data)
            return redirect(url_for('index'))
        else:
            flash('Invalid Credentials')
    return render_template('admin_login.html', form=form)

@app.route('/')
@app.route('/index')
def index():
    if auth():
        return render_template('index.html', title = "Home", user = current_user)
    return redirect(url_for('login'))

@app.route('/account')
def account():
    return render_template('account.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/add_flight')
def add_flight():
    if current_user.email == 'admin@admin.com':
        return render_template('add_flight.html')
    return redirect(url_for('index'))

@app.route('/remove_flight')
def remove_flight():
    if current_user.email == 'admin@admin.com':
        return render_template('remove_flight.html')
    return redirect(url_for('index'))    


api.add_resource(CREATE_FLIGHT,"/create_flight")
api.add_resource(SEARCH_FLIGHT,"/search")
api.add_resource(REMOVE_FLIGHT_API,"/remove")
api.add_resource(BOOK_FLIGHT,"/book")



if __name__ == '__main__':
    app.debug = True
    app.run()