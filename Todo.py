import os
from flask import Flask
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