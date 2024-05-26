import os
from sqlite3 import IntegrityError

from flask import Flask, url_for, request, render_template, make_response, redirect, session, flash, current_app
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import session
import db
import logging
import bcrypt
import hashlib


###### HASH
def get_hashed_password(password, salt):
    return bcrypt.hashpw(password, salt)




##### APP
app = Flask(__name__)
app.secret_key = "a336f4c864f061eee326c2db31253504a66bb307f893d6bb035e0beb63993052" #todo SECURE SECRET KEY

###### DB
#app.wsgi_app = ProxyFix(app.wsgi_app) # wsgi middleware
DATABASE = 'db/db_api.db'
app.config['DATABASE'] = DATABASE
db.init_app(app)
def get_error_output(error):
    if 'UNIQUE' in error:
        if 'Login' in error:
            return "Given login already exists! Choose other!"
        elif 'Email' in error:
            return "Given email already exists! Choose other!"
    else:
        return error

###### CONTROLLERS
@app.route('/')
def index():
    if 'username' in session:
        flash(f'Logged in as {escape(session["username"])}')
        return render_template('index.html')
    flash("You are not logged in!")
    return render_template('notlogged.html')


@app.route('/send', methods=['GET', 'POST'])
def message():
    if 'username' not in session: # user is not in session
        flash("You are not logged in")
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = session['username']
        message = f'{escape(request.form['message'])}'
        db_conn = db.get_db()
        user = db_conn.execute('SELECT Id FROM User WHERE Login = (?)', [username]).fetchone()
        print(user, "XDD")
        if user is None:
            flash("User not found")
            return redirect(url_for('index'))

        user_id = user['id']

        db_conn.execute(
            'INSERT INTO Message (Text, UserId) VALUES (?, ?)', (message, user_id))

        db_conn.commit()

        flash('Message \'' + message + "\' was sent to the database!")
        return redirect(url_for('index'))
    return render_template('message.html')


@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    error = None
    if request.method == 'POST':
        try:
            login = f'{escape(request.form['username'])}'
            session['username'] = login
            password = f'{escape(request.form['password'])}'
            email = f'{escape(request.form['email'])}'
            salt = bcrypt.gensalt() # will be 29 chars
            hashedpassword = get_hashed_password(password.encode('utf-8'), salt)

            db_conn = db.get_db()
            db_conn.execute(
                'INSERT INTO User (Login, Password, Email, Salt) VALUES (?,?,?,?)', (login,hashedpassword,email,salt)
            )
            flash("You were successfully logged in!")
            db_conn.commit()
            return redirect(url_for('index'))
        except Exception as e:
            print(e)
            error = get_error_output(str(e))
    return render_template('sign_in.html', error=error)

@app.route('/login',methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db_conn = db.get_db()

        print(username, "USERNAME")
        user_data = db_conn.execute('SELECT Password, Salt FROM User WHERE Login = (?)', [username]).fetchone()
        print(user_data)
        if user_data is None:
            flash("User not found")
            return redirect(url_for('index'))

        stored_password = user_data['password']
        salt = user_data['salt']

        if get_hashed_password(password.encode('utf-8'),salt) == stored_password:
            session['username'] = username
            flash("You were successfully logged in!")
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password.'
    return render_template('login.html',error=error)

    flash("Maybe create an account!")
    return render_template('index.html')
@app.route('/messages', methods=['GET'])
def messages():
    db_conn = db.get_db()
    messages = db_conn.execute(
        'SELECT m.Text, u.Login FROM Message m JOIN User u ON m.UserId = u.Id'
    ).fetchall()
    return render_template('messages.html', messages=messages)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))
