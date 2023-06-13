import os
from datetime import datetime
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
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    passwordhash = db.Column(db.String(128))
    todos = db.relationship('Todo', backref='user', lazy='dynamic')
    
    def __repr__(self):
        return self.email
    
    def my_genrate_password_hash(self,password_raw):
        self.passwordhash = generate_password_hash(password_raw)
        
    def check_password(self,password_raw):
        return check_password_hash(self.passwordhash,password_raw)

class  Todo(db.Model):
    __tablename__ = 'todos'
    id = db.Column(db.Integer,primary_key=True)
    author = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(32),unique=False)
    note = db.Column(db.Text(),unique=True)
    done =  db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(), default=datetime.utcnow)
    
    def __repr__(self):
        return self.title  
    
    def from_json_update(self,todo_json):
        title = todo_json.get('title',self.title)
        done = todo_json.get('done',self.done)
        note = todo_json.get('note',self.note)
        self.title = title
        self.done = done
        self.note = note
        db.session.add(self)
        db.session.commit()
        return self
    
    def get_author(self,author_id):
        
        user=User.query.filter_by(id=author_id).first()
        data={'email':user.email}
        return data
    
    def to_json(self):
        json_post = {
        'id':self.id,
        'note': self.note,
        'title':self.title,
        'done':self.done,
        'created_at': self.created_at,
        'author':self.get_author(self.author)
        }
        return json_post  
        
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
    if not password and not email:
        return {'message':'send password and email'}
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
        
def is_author_object(requsted_user,object_author):
    if requsted_user.id == object_author:
        return True,{}
    else:
        return False,{'messeage':'Must be own todo'}


def required_login(req):
    try:            
        tk = req.authorization.token
    except:
        return {'messeage':'you have to login'},False
    else:
        return tk,True


      
def get_user_by_token(token):
    user = UserToken.query.filter_by(token=token).first()
    if user:
        return User.query.filter_by(id=user.id).first()
    return None


@app.route('/login',methods=['POST'])
def login():
    return jsonify(json_login(request.json))  

@app.route('/todos')
def todo_list():
    data, status = required_login(request)
    if not status:
        return jsonify(data)
    user = get_user_by_token(data)
    todo_list = Todo.query.filter_by(author=user.id).all()
    return jsonify({ 'todos': [todo.to_json() for todo in todo_list] })
    
@app.route('/todos/<pk>/',methods=['PUT'])
def todo_edit(pk):
    data, status = required_login(request)
    if not status:
        return jsonify(data)
    todo = Todo.query.filter_by(id=pk).first()
    is_author,msg = is_author_object(get_user_by_token(data),todo.author)
    if is_author:
        result = todo.from_json_update(request.json)
        return jsonify({'todo':result.to_json()})
    else:
        return jsonify(msg),401
    