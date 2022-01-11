"""This program uses flask to create a simple website"""
import csv
import logging
import logging.config
import os
import re
from datetime import datetime
import yaml


import flask
from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import Form
from passlib.hash import sha256_crypt
from wtforms import TextField

app = Flask(__name__)
app.config['SECRET_KEY'] = 'our very hard to guess secret'
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
logging.config.dictConfig(yaml.load(open('logging.conf')))


@app.route('/')
def index():
    """This function renders index html file, gives title, and returns date/time"""
    return render_template('index.html', the_title='Login Page', date=datetime.now())


@app.route('/main')
def main():
    """This function renders main html file, gives title, and returns date/time"""
    if not session['authenticated']:
        return redirect(url_for('index', date=datetime.now()))
    return render_template('main.html', the_title='Battle.net Home Page', date=datetime.now())


@app.route('/warzone.html')
def warzone():
    """This function renders warzone html file, gives title, and returns date/time"""
    if not session['authenticated']:
        return redirect(url_for('index', date=datetime.now()))
    return render_template('warzone.html', the_title='Call of Duty: Warzone',
                           date=datetime.now())


@app.route('/wow.html')
def wow():
    """This function renders wow html file, gives title, and returns date/time"""
    if not session['authenticated']:
        return redirect(url_for('index', date=datetime.now()))
    return render_template('wow.html', the_title='World of Warcraft', date=datetime.now())


class RegistrationForm(Form):
    """Class created for registration form"""
    username = TextField('Username')
    password = TextField('Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """This function renders register html file,
    provides user with registration form, gives title, and returns date/time"""
    error = ""
    form = RegistrationForm(request.form)

    if request.method == 'POST':
        username = form.username.data
        password = form.password.data

        if len(username) == 0 or len(password) == 0:
            error = "Please enter both a username and password."

        elif check_not_reg(username) is not None:
            error = "Username taken."

        elif not password_check(password):
            error = "Password does not meet complexity requirement."

        elif password_check(password):
            flask.flash('Thank you for registering.')
            with open("Login.txt", "a") as file:
                file.write(username)
                file.write(" ")
                hash_pass = sha256_crypt.hash(password)
                file.write(hash_pass)
                file.write("\n")
            return redirect(url_for('index'))

    return render_template('register.html', form=form, message=error, date=datetime.now())


class LoginForm(Form):
    """Class created for login form"""
    username = TextField('Username')
    password = TextField('Password')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """This function renders login html file,
    provides user with login form, gives title, and returns date/time"""
    error = ""
    form = LoginForm(request.form)

    if request.method == 'POST':
        username = form.username.data
        password = form.password.data

        if len(username) == 0 or len(password) == 0:
            error = "Please enter both a username and password."

        elif check_not_reg(username) == password:
            flask.flash('Logged in successfully.')

            session['authenticated'] = True

            return redirect(url_for('main', date=datetime.now()))

        elif check_not_reg(username) != password:
            error = "Username or password is incorrect."

    return render_template('login.html', form=form, error=error, date=datetime.now())


class ChangePasswordForm(Form):
    """Class created for change password form"""
    username = TextField('Username')
    password = TextField('Password')


@app.route('/change_pass', methods=['GET', 'POST'])
def change_pass():
    """This function renders change_pass html file,
    provides user with change password form, gives title, and returns date/time"""
    if not session['authenticated']:
        return redirect(url_for('index', date=datetime.now()))

    error = ""
    form = ChangePasswordForm(request.form)

    if request.method == 'POST':
        username = form.username.data
        password = form.password.data

        updated_list = []

        if len(username) == 0 or len(password) == 0 or len(password) == 0:
            error = "Please enter both a username and password."

        elif not password_check(password):
            error = "Password does not meet complexity requirement."

        elif check_not_sec(password) is not None:
            error = "Please use a secure password."

        elif password_check(password):
            with open("Login.txt", newline="") as users:
                reader = csv.reader(users)

                for row in reader:
                    for field in row:
                        if field == username:
                            updated_list.append(row)
                            updated_list[0][1] = password

                update_password(updated_list)
                flask.flash('Password change successful.')
                return redirect(url_for('main'))

    return render_template('change_pass.html', form=form,
                           the_title='Change Password', message=error,
                           date=datetime.now())


def update_password(updated_list):
    """This function is suppose to change the password in my text file"""
    file = "Login.txt"
    temp_file = file + ".tmp"

    try:
        with open(temp_file, "x", newline="") as users:
            writer = csv.writer(users)
            writer.writerows(updated_list)
            users.flush()
            os.fsync(users.fileno())
        os.replace(temp_file, file)
        temp_file = None

    except FileExistsError:
        print("Another copy is running or stale tempfile exists")
        temp_file = None  # tempfile does not belong to this process
    except OSError as err:
        print("Error: {}".format(err))
    finally:
        if temp_file:
            try:
                os.unlink(temp_file)
            except OSError:
                print("Could not delete the tempfile")


def check_not_reg(username):
    """ Check if the given username does not already exist in our password file
        return none of the username does not exist; otherwise return the password for that user
    """
    try:
        with open("Login.txt", "r") as users:
            for record in users:
                if len(record) == 0:
                    print('password file is empty')
                    return None
                username1, password1 = record.split()
                if username1 == username:
                    return password1
    except FileNotFoundError:
        print('File not found: ' + "Login.txt")
        os.abort()  # Flask method to abort the whole web app
    except Exception as log:
        logging.exception(log)
        os.abort()  # Flask method to abort the whole web app
    return None


def check_not_sec(password):
    """ Check if the given username does not already exist in our password file
        return none of the username does not exist; otherwise return the password for that user
    """
    try:
        with open("CommonPassword.txt", "r") as secrets:
            for record in secrets:
                if len(record) == 0:
                    print('password file is empty')
                    return None
                if record == password:
                    return password
    except FileNotFoundError:
        print('File not found: ' + "CommonPassword.txt")
        os.abort()
    except Exception as log:
        logging.exception(log)
        os.abort()
    return None


def password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        12 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) < 12

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~" + r'"]', password) is None

    # overall result
    password_ok = not (length_error or digit_error or uppercase_error
                       or lowercase_error or symbol_error)

    return bool(password_ok)


@app.route('/logout')
def logout():
    """This function logs out the user and ends the session"""
    session.pop('auth_token', None)
    session.pop('authenticated', None)
    return redirect(url_for('index'))


logfile = logging.getLogger('file')
log_console = logging.getLogger('console')
logfile.debug("Debug FILE")
log_console.debug("Debug CONSOLE")
logging.config.dictConfig(yaml.load(open('logging.conf')))

# Run the application
app.run(debug=True)
