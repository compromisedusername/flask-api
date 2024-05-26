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
from celery import Celery


###### HASH
async def get_hashed_password(password, salt):
    return bcrypt.hashpw(password, salt)

##### APP
app = Flask(__name__)
app.secret_key = "a336f4c864f061eee326c2db31253504a66bb307f893d6bb035e0beb63993052" #todo SECURE SECRET KEY

##### CELERY
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

async def make_celery(app):
    celery =  Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    TaskBase = celery.Task
    class ContextTask(TaskBase):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return  TaskBase.__call__(self, *args, **kwargs)
    celery.Task = ContextTask
    return celery

celery = make_celery(app)

@celery.task
async def insert_message_task(message, user_id):
    db_conn = await db.get_db()
    await db_conn.execute('INSERT INTO Message (Text, UserId) VALUES (?, ?)', (message, user_id))
    await db_conn.commit()

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
async def index():
    if 'username' in session:
        flash(f'Logged in as {escape(session["username"])}')
        return render_template('index.html')
    flash("You are not logged in!")
    return render_template('notlogged.html')


@app.route('/send', methods=['GET', 'POST'])
async def message():
    if 'username' not in session: # user is not in session
        flash("You are not logged in")
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = session['username']
        message = f'{escape(request.form['message'])}'
        db_conn = db.get_db()
        user = await db_conn.execute('SELECT Id FROM User WHERE Login = (?)', [username]).fetchone()

        if user is None:
            flash("User not found")
            return redirect(url_for('index'))

        user_id = user['id']

        await insert_message_task.delay(message,user_id)

        flash('Message \'' + message + "\' was sent to the database!")
        return redirect(url_for('index'))
    return render_template('message.html')


@app.route('/sign_in', methods=['GET', 'POST'])
async def sign_in():
    error = None
    if request.method == 'POST':
        try:
            login = f'{escape(request.form['username'])}'
            session['username'] = login
            password = f'{escape(request.form['password'])}'
            email = f'{escape(request.form['email'])}'
            salt = bcrypt.gensalt() # will be 29 chars
            hashedpassword = await get_hashed_password(password.encode('utf-8'), salt)

            db_conn = await db.get_db()
            await db_conn.execute(
                'INSERT INTO User (Login, Password, Email, Salt) VALUES (?,?,?,?)', (login,hashedpassword,email,salt)
            )
            await db_conn.commit()
            flash("You were successfully logged in!")
            return redirect(url_for('index'))
        except Exception as e:
            print(e)
            error = get_error_output(str(e))
    return render_template('sign_in.html', error=error)

@app.route('/login',methods=['GET', 'POST'])
async def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db_conn = await db.get_db()


        user_data = await db_conn.execute('SELECT Password, Salt FROM User WHERE Login = (?)', [username]).fetchone()

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
async def messages():
    db_conn = await db.get_db()
    messages = await db_conn.execute(
        'SELECT m.Text, u.Login FROM Message m JOIN User u ON m.UserId = u.Id'
    ).fetchall()
    return render_template('messages.html', messages=messages)


@app.route('/logout')
async def logout():
    session.pop('username', None)
    return redirect(url_for('index'))
