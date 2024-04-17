from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from os import path
from flask_login import LoginManager
import random
import secrets


def createsalt():
    ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars=[]
    num = random.randint(20,50) #salt should be at least 32 bytes long min(20+12)
    for i in range(num):
        chars.append(random.choice(ALPHABET))
        x = list(secrets.token_hex(12))
        osalt = x + chars
        random.shuffle(osalt)
        salt = "".join(osalt)
    return salt

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)
    secret = createsalt()
    uri = os.getenv("DATABASE_URL")  # or other relevant config var
    if uri.startswith("postgres://"): # from SQLAlchemy 1.14, the uri must start with postgresql, not postgres, which heroku provides
        uri = uri.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = uri
    app.config['SECRET_KEY'] = secret
    db = SQLAlchemy()
    db.init_app(app)

    from .views import views
    from .auth import auth
    
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    
    from .models import User, Note
    
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    return app




#def create_database(app):
 #  if not path.exists('website/' + DB_NAME):
  #      db.create_all(app=app)
   #     print('Created Database!')
        
