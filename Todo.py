import os
from uuid import uuid4
from flask import Flask,jsonify,request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from flask_migrate import Migrate
app = Flask(__name__) 

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

#Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    passwordhash = db.Column(db.String(128))
    
    def __repr__(self):
        return self.email
    
    def my_genrate_password_hash(self,password_raw):
        self.passwordhash = generate_password_hash(password_raw)
        
    def check_password(self,password_raw):
        return check_password_hash(self.passwordhash,password_raw)
    
    
class UserToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128),default=str(uuid4()))
    user = db.Column(db.Integer)


def check_user_token(userid):
    token = UserToken.query.filter_by(user=userid).first()
    if token:
        return token.token
    new_token = UserToken(user=userid)
    db.session.add(new_token)
    db.session.commit()
    return new_token.token
    
def json_login(json_login_data):
    
    password = json_login_data.get('password')
    email = json_login_data.get('email')
    user=User.query.filter_by(email=email).first()
    if user is None:
        return {'message':'User Not Found'}
    elif user:
        result=user.check_password(password)
        if result:
            token=check_user_token(user.id)
            return {"message": "Login was success",'token':token}
        else:
            return {'message':'Email,Password is Wrong'}

   
def get_user_by_token(token):
    user = UserToken.query.filter_by(token=token).first()
    if user:
        return User.query.filter_by(id=user.id).first()
    return None


@app.route('/login',methods=['POST'])
def login():
    print(get_user_by_token(request.authorization.token))
    return jsonify(json_login(request.json))  