from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from .models import Logg
import re
import random
import secrets
from flask import session
from argon2 import PasswordHasher
from argon2.exceptions import *

hidden_user = 1
auth = Blueprint('auth', __name__)

def has_numbers(inputString):
    check = sum(1 for x in inputString if x.isdigit())
    if check >= 2:
        return True
    else:
        return False

def has_string(name, password):
    if name in password:
        return True
    else:
        return False

def has_numbers_one(inputString):
     return any(char.isdigit() for char in inputString)

def has_capital(inputString):
    return any(char.isupper() for char in inputString)

def has_lower(inputString):
    return any(char.islower() for char in inputString)

def valid_email(inputmail):
    regex = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}'
    if(re.fullmatch(regex,inputmail)):
        return True
    else:
        return False

def createsalt():
    ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars = []
    num = random.randint(20,50) #salt should be at least 32 bytes long min(20+12)
    for i in range(num):
        chars.append(random.choice(ALPHABET))
        x = list(secrets.token_hex(12))
        osalt = x + chars
        random.shuffle(osalt)
        salt = "".join(osalt)
    return salt

def has_char(inputString):
    chars = set(' !"#$%&()*+,-./:;<=>?@[\]^_`{|}~')
    if any((c in chars) for c in inputString):
        return True
    else:
        return False

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ph = PasswordHasher()
        email = request.form.get('email')
        password = request.form.get('password')
        number_failedattempts = 0
        if email == "" or password == "":
            flash('Fill out all forms to login', category='error')
            return render_template("login.html", user=current_user)
        get_user = db.session.query(User)
        salt = ""
        for user in get_user:#
            if user.email == email:#
                salt = str(user.salt)#
                number_failedattempts = int(user.failed_login)
        password = salt + password + salt + salt + "fg!§!!!!§"
        user = User.query.filter_by(email=email).first()
        if user:
            if user.role == "Admin" and user.id != 1:
                flash('You are not the real admin', category='error')
                user.failed_login = 5
                return render_template("login.html", user=current_user)
            if number_failedattempts >= 5: #fjern and user != 1 for å kunne låse addmin bruker
                flash('This Account is locked contact the admin to unlock your Account', category='error')
                return render_template("login.html", user=current_user)
            try:
                isValid = ph.verify(user.password, password)
            except (VerifyMismatchError, HashingError, InvalidHash, VerificationError):
                isValid = False
            if isValid == True:
                flash('Logged in successfully!', category='success')
                message =f" User {str(user.first_name)} has logged inn!"#
                new_logg = Logg(event=message,user_id= user.id)
                db.session.add(new_logg)
                db.session.commit()
                login_user(user, remember=True)
                if user.id == 1:
                    return redirect(url_for('views.home'))
                else:
                    counter = 0
                    login_info = User.query.filter_by(id= user.id).first()
                    login_info.failed_login = counter
                    db.session.commit()
                    return redirect(url_for('views.home'))
            else:
                session.permanent = True #<-----
                login_info = User.query.filter_by(id= user.id).first()
                login_info.failed_login += 1
                db.session.commit()
                message = f"Failed login attempt"
                new_logg = Logg(event=message, user_id= user.id)
                db.session.add(new_logg)
                db.session.commit()
                message = "Incorrect password, try again. You have "+str(5-number_failedattempts)+" tries left"
                flash(message, category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    get_user = db.session.query(User)
    for user in get_user:#
        if user.id == current_user.id:#
            user.logged_on = "No"
            db.session.commit()
    message =f" User {str(current_user.first_name)} has logged out!"#
    new_logg = Logg(event=message,user_id= current_user.id)
    db.session.add(new_logg)
    db.session.commit()
    session.clear()
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        ph = PasswordHasher()
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif email == "" or first_name == "" or password1 == "" or password2 == "" :
            flash('Fill out all forms to sign-up', category='error')
        elif has_string(email,password1) == True:
            flash('Don\'t use your email as password.', category='error')
        elif has_string(first_name,password1) == True:
            flash('Don\'t use your name as password.', category='error')
        elif len(email) <= 8 and len(email) >= 20:
            flash('Email must be greater than 8 characters.', category='error')
        elif len(first_name) < 2 and len(first_name) >=20:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) <= 8 and len(password1) >= 20:
            flash('Password must be at least 8 characters.', category='error')
        elif has_numbers(password1) == False:
            flash('Password must contain at least two numbers.', category='error')
        elif valid_email(email) == False:
            flash('Not a valid email', category='error')
        elif has_capital(password1) == False:
            flash('Password must contain at least one capital letter.', category='error')
        elif has_lower(password1) == False:
            flash('Password must contain at least one lower case letter.', category='error')
        elif has_char(password1) == False:
            flash('Password must contain at least one special character', category='error')
        elif has_char(first_name) == True:
            flash('Usernames cant have characters', category = 'error')
        elif has_numbers_one(first_name) == True:
            flash('Usernames cant have numbers', category= 'error')
        else:
            salt = createsalt()
            password1 = salt + password1 + salt + salt + "fg!§!!!!§"
            role = "User"
            try:
                new_user = User(failed_login =0, logged_on = "Yes", role=role, email=email, first_name=first_name,salt=salt, password=ph.hash(
                    password1))
                db.session.add(new_user)
                db.session.commit()
                if new_user.id == hidden_user:
                    new_user.role = "Admin"
                    db.session.commit()
                message =f" A new account has been made for user {str(new_user.first_name)}"#
                new_logg = Logg(event=message,user_id= new_user.id)
                db.session.add(new_logg)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))
            except(VerifyMismatchError, HashingError, InvalidHash, VerificationError):
                flash('Action failed', category= 'error')
    return render_template("sign_up.html", user=current_user)
