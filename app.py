from flask import Flask, url_for, request, render_template, make_response, redirect, session, flash, current_app
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import session
from . import db
DATABASE = 'db/db_api.db'




##### APP


#app.wsgi_app = ProxyFix(app.wsgi_app) # wsgi middleware

###### DB
app = Flask(__name__)
app.secret_key = "a336f4c864f061eee326c2db31253504a66bb307f893d6bb035e0beb63993052"
db.init_app(app)

###### CONTROLLERS
@app.route('/')
def index():
    if 'username' in session:
        flash(f'Logged in as {escape(session["username"])}')
        return render_template('index.html')
    return 'You are not logged in'


@app.route('/message', methods=['GET', 'POST'])
def message():
    if 'username' not in session:
        flash("You are not logged in")
        return redirect(url_for('login'))
    if request.method == 'POST':
        message = f'{escape(request.form['message'])}'
        flash('Message \'' + message + "\'was sended to database!")
        return redirect(url_for('index'))
    return render_template('message.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        session['username'] = request.form['username']
        flash("You were successfully logged in!")
        return redirect(url_for('index'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))
