################################# Essential Imports #################################
from datetime import datetime
from pwdlapp import db, login_manager
from flask_login import UserMixin


################################# Login Manager #################################
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


################################# User Class #################################
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    secret =db.Column(db.String, unique=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"


################################# Post Class #################################
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"
    

################################# Encryption File Class #################################
class Encfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(20), nullable=False)
    key = db.Column(db.String, unique=True, nullable=False)
    uid = db.Column(db.String, nullable=False)
    result = db.Column(db.String, nullable=False)
    file_name = db.Column(db.String, nullable=False)