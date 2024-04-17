from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from .models import Note
from .models import User
from .models import Logg
from . import db
from .auth import *
import json
import random
from flask import render_template
from . import createsalt
from argon2 import PasswordHasher
from argon2.exceptions import *

views = Blueprint('views', __name__)
falied_login = 0
@views.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    get_user = db.session.query(User)
    get_logg = db.session.query(Logg)
    get_note = db.session.query(Note)
    logg_number = 0
    user_number = 0
    account_number = 0
    verdi = 0

    for user in get_user:#
        if user.id != 0:
            user_number = user_number + 1
        if user.id == current_user.id:#
            user.logged_on = "Yes"
            db.session.commit()
    for user in get_logg:
        if user.logg_id != 0:
            logg_number = logg_number + 1
    for user in get_note:#
        if user.id != 0:
            account_number = account_number + 1
    ph = PasswordHasher()
    if current_user.id != 1:
        user = User.query.filter_by(id=current_user.id).first()
        user.failed_login = 5
        db.session.commit()
        message = f"User: {str(current_user.first_name)} id: {str(current_user.id)}, tried to access the admin page."
        new_logg = Logg(event=message,user_id=1)
        db.session.add(new_logg)
        db.session.commit()
        render_template("login.html", user=current_user)
        logout_user()
        flash('You should\'t have tried that! Your account is now locked.', category='error')
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        if"CancelButton" in request.form:
            verdi = 0
        if"UserButton" in request.form:
            last_entry = request.form.get('FilterLastEntry1')
            verdi = 1
            if isinstance(last_entry,str)  and len(last_entry) > 0 and last_entry.isdecimal():
                last_entry_int = int(last_entry)
                column_number = db.session.query(User).count()
                if last_entry_int <= column_number:
                    the_offset = column_number - last_entry_int
                    query = db.session.query(User).offset(the_offset)
                    get_user = query
                else:
                    flash('Error', category='success')
                    verdi = 0
            else:
                flash('Error', category='success')
                verdi = 0
        if"ButtonAccount" in request.form:
            last_entry = request.form.get('FilterLastEntry2')
            verdi = 2
            if isinstance(last_entry,str)  and len(last_entry) > 0 and last_entry.isdecimal():
                last_entry_int = int(last_entry)
                column_number = db.session.query(Note).count()
                if last_entry_int <= column_number:
                    the_offset = column_number - last_entry_int
                    query = db.session.query(Note).offset(the_offset)
                    get_note = query
                else:
                    flash('Error', category='success')
                    verdi = 0
            else:
                flash('Error', category='success')
                verdi = 0
        if"LoggButton" in request.form:
            last_entry = request.form.get('FilterLastEntry3')
            verdi = 3
            if isinstance(last_entry,str)  and len(last_entry) > 0 and last_entry.isdecimal():
                last_entry_int = int(last_entry)
                column_number = db.session.query(Logg).count()
                if last_entry_int <= column_number:
                    the_offset = column_number - last_entry_int
                    query = db.session.query(Logg).offset(the_offset)
                    get_logg = query
                else:
                    flash('Error', category='success')
                    verdi = 0
            else:
                flash('Error', category='success')
                verdi = 0
        if"DeleteUser" in request.form:
            new_id = request.form.get('DeleteUser')
            user = User.query.filter_by(id=new_id).first()
            if new_id == "" or new_id == "1" or new_id.isdecimal() == False or user == None:
                flash('Admin needs to think about his actions', category='error')
            else:
                delete_id = int(new_id)
                obj = User.query.filter_by(id=delete_id).one()
                db.session.delete(obj)
                db.session.commit()
        if"NewPassword" in request.form:
            userID = request.form.get('UserID')
            user = User.query.filter_by(id=userID).first()
            if userID == "" or userID == "1" or userID.isdecimal() == False or user == None:
                flash('Admin needs to think about his actions!', category='error')
            else:
                new_password = request.form.get('new_password')
                if has_capital(new_password) == False:
                    flash('Password must contain at least one capital letter.', category='error')
                elif user.email == new_password:
                    flash('Dont use include your email as password.', category='error')
                elif user.first_name == new_password:
                    flash('Dont use include your name as password.', category='error')
                elif len(new_password) <= 8 and len(new_password) >= 20:
                    flash('Password must be at least 8 characters.', category='error')
                elif has_numbers(new_password) == False:
                    flash('Password must contain at least two numbers.', category='error')
                elif has_lower(new_password) == False:
                    flash('Password must contain at least one lower case letter.', category='error')
                elif has_char(new_password) == False:
                    flash('Password must contain at least one special character', category='error')
                else:
                    the_user = int(userID)
                    for user in get_user:
                        if user.id == the_user:
                            ny_salt = createsalt()
                            salt = str(ny_salt)
                            user.salt = salt
                            db.session.commit()
                            new_password = salt + new_password + salt + salt + "fg!§!!!!§"
                            try:
                                password2 = ph.hash(new_password)
                                user.password =password2
                                db.session.commit()
                            except (VerifyMismatchError, HashingError, InvalidHash, VerificationError):
                                flash('Action failed', category= 'error')
        if"ResetUser" in request.form:
            new_id = request.form.get('ResetUser')
            user = User.query.filter_by(id=new_id).first()
            if new_id == "" or new_id == "1" or new_id.isdecimal() == False or user == None:
                flash('Admin needs to think about his actions!', category='error')
            else:
                for user in get_user:
                    if user.id == int(new_id):
                        user.failed_login = 0
                        db.session.commit()
        if"LockUser" in request.form:
            new_id = request.form.get('LockUser')
            user = User.query.filter_by(id=new_id).first()
            if new_id == "" or new_id == "1" or new_id.isdecimal() == False or user == None:
                flash('Admin needs to think about his actions!', category='error')
            else:
                for user in get_user:
                    if user.id == int(new_id) and user.id != 1:
                        user.failed_login = 4
                        db.session.commit()
    return render_template("admin.html", user=current_user, get_user =get_user , verdi =verdi,  get_logg = get_logg,get_note = get_note, user_number = user_number, logg_number = logg_number, account_number = account_number)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    delete_value = 0
    get_user = db.session.query(User)
    get_logg = db.session.query(Logg)
    verdi = 0
    logg_number = 0
    for user in get_logg:
        if user.logg_id != 0 and user.user_id == current_user.id:
            logg_number = logg_number + 1
    for user in get_user:
        if user.id == current_user.id:
            user.logged_on = "Yes"
            db.session.commit()
    if request.method == 'POST':
        tabell_note = db.session.query(Note.user_id)
        ny_tabell =db.session.query(Note)
        sender = request.form.get("sender")
        mottaker = request.form.get("resiver")
        betaling = request.form.get("payment")
        info_user = db.session.query(User)
        failed_attempts = 0
        for index in info_user:
            if index.id == current_user.id:
                failed_attempts = index.failed_login
        if 'AccountButton' in request.form:
            number_accounts = 0
            if failed_attempts <= 5:
                for notes in tabell_note:
                    if notes.user_id == current_user.id:
                        number_accounts = number_accounts + 1
            else:
                number_accounts = 10
            if number_accounts >= 5:
                flash('Maximun account number reached, please delete at least one account.', category='success')
            else:
                account_random = random.randint(1000,100000)#
                new_note = Note(data=account_random, user_id=current_user.id)
                db.session.add(new_note)
                db.session.commit()
                message = "Account: "+str(new_note.id)+" with £"+str(new_note.data)+" added."
                new_logg = Logg(event=message,user_id= current_user.id)
                db.session.add(new_logg)
                db.session.commit()
                flash(message, category='success')
        if 'PaymentButton' in request.form:
            if isinstance(sender, str) and isinstance(mottaker, str) and isinstance(betaling, str) and len(sender) >0 and len(mottaker) > 0 and len(betaling) > 0 and failed_attempts <= 5:
                if sender[0] != " " and mottaker[0] != " " and betaling[0] != " ":
                    if sender[0] != "0" and mottaker[0] != "0" and betaling[0] != "0":
                        if sender.isdecimal() and mottaker.isdecimal() and betaling.isdecimal():
                            if sender != mottaker:
                                sender_int = int(sender)
                                mottaker_int = int(mottaker)
                                betaling_int = int(betaling)
                                tabell_sender = []
                                tabell_mottaker = []
                                for notes in ny_tabell:#Mod
                                    tabell_mottaker.append(int(notes.id))
                                    if notes.user_id == current_user.id: #denne er feil
                                        tabell_sender.append(int(notes.id))
                                if sender_int in tabell_sender:
                                    if mottaker_int in tabell_mottaker:
                                        sender_info = Note.query.filter_by(id = sender_int).first()
                                        mottaker_info = Note.query.filter_by(id = mottaker_int).first()
                                        mottakernavn = User.query.filter_by(id = mottaker_info.user_id).first()
                                        sender_totalt_belop =sender_info.data
                                        mottaker_totalt_belop = mottaker_info.data
                                        sender_totalt_belop_int = int(sender_totalt_belop)
                                        mottaker_totalt_belop_int = int(mottaker_totalt_belop)
                                        if mottaker_totalt_belop_int < 99999999999999 and sender_totalt_belop_int >= betaling_int and sender_totalt_belop_int > 0 and sender_int != mottaker_int:
                                            ny_belop_sender = sender_totalt_belop_int -betaling_int
                                            ny_belop_mottaker = mottaker_totalt_belop_int + betaling_int
                                            sender_info.data =ny_belop_sender
                                            db.session.commit()
                                            mottaker_info.data =ny_belop_mottaker
                                            db.session.commit()
                                            if current_user.first_name == mottakernavn.first_name:
                                                message = str('Account: '+sender+" sent £"+betaling+" to Account: "+mottaker+".")
                                                new_logg = Logg(event=message,user_id= current_user.id)
                                                db.session.add(new_logg)
                                                db.session.commit()
                                                flash(message, category='success')
                                            else:
                                                message = str('Account: '+sender+" sent £"+betaling+" to user "+mottakernavn.first_name+"'s Account: "+mottaker+".")
                                                new_logg = Logg(event=message,user_id= current_user.id)
                                                db.session.add(new_logg)
                                                db.session.commit()
                                                more_money = str('User: '+current_user.first_name+' sent you £'+betaling+' to your Account:'+mottaker)
                                                new_logg = Logg(event=more_money,user_id=mottakernavn.id)
                                                db.session.add(new_logg)
                                                db.session.commit()
                                                flash(message, category='success')
                                        else:
                                            flash('Need more money!', category='error')
                                    else:
                                        message = str("Tried to send money to non-existent Account: "+mottaker)
                                        new_logg = Logg(event=message,user_id= current_user.id)
                                        db.session.add(new_logg)
                                        db.session.commit()
                                        flash('The account you are trying to send to doesn\'t exist!', category='error')
                                else:
                                    message = str("Tried to send money from Account: "+sender+" which doesn\'t belong to you!")
                                    new_logg = Logg(event=message,user_id= current_user.id)
                                    db.session.add(new_logg)
                                    db.session.commit()
                                    flash('That account doesn\'t belong to you!', category='error')
                            else:
                                message = str("Tried to send money to the same Account you were sending from")
                                new_logg = Logg(event=message,user_id= current_user.id)
                                db.session.add(new_logg)
                                db.session.commit()
                                flash('Can\'t send money to same account!', category ='error')
                        else:
                            flash('Only numbers allowed!', category='error')
                    else:
                        flash('0 is not a valid first number!', category='error')
                else:
                    flash('That character is not a valid input!', category='error')
            else:
                flash('Fill out all forms!', category='error')
        if "CornfirmButton" in request.form:
            delete_value = 1
        if"UserLogg" in request.form:
            verdi = 4
            query1 = db.session.query(Logg).filter_by(user_id =current_user.id)
            get_logg = query1
    return render_template("home.html", user=current_user, delete_value = delete_value, verdi = verdi, get_logg = get_logg,logg_number = logg_number )

@views.route('/delete-note', methods=['POST'])
def delete_note():
    info_user = db.session.query(User)
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    failed_attempts = 0
    for index in info_user:
        if index.id == current_user.id:
            failed_attempts = index.failed_login
    if note:
        if note.user_id == current_user.id and failed_attempts <= 5 :
            db.session.delete(note)
            db.session.commit()
            message =f"User {str(current_user.first_name)} has deleted account {str(note.id)}"#
            new_logg = Logg(event=message,user_id= current_user.id)
            db.session.add(new_logg)
            db.session.commit()
        else:
            flash('Locked User', category='success')
    return jsonify({})
