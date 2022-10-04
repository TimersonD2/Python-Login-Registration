
from flask import render_template, request, redirect, flash, session
from flask_app.models.user import User
from flask_app import app

from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/validateReg', methods=["POST"])
def validateReg():
    if len (request.form['first_name']) < 2:
        flash('The first name must minimum of 2 characters')
        return redirect('/')

    if len (request.form['last_name']) < 2:
        flash('The last name must minimum of 2 characters')
        return redirect('/')

    if not User.validateEmail(request.form):
        flash('The email address was not valid')
        return redirect('/')

    if User.get_one_email(request.form):
        flash('The email address already exists')
        return redirect('/')
    
    if len (request.form['password']) < 8:
        flash('The password must be at least 8 characters long')
        return redirect('/')

    if request.form['password'] != request.form['confirm']:
        flash('The password and confirm password did not match')
        return redirect('/')

    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    print(pw_hash)

    data = {
        "first_name" : request.form['first_name'],
        "last_name" : request.form['last_name'],
        "email" : request.form["email"],
        "password" : pw_hash,
    }
    user_id = User.save(data)
    session['user_id'] = user_id
    session['email'] = request.form['email']
    session['route'] = 'register'

    return redirect('/success')

@app.route('/success')
def showUser():
    if not session:
        return redirect('/')

    data = {
        "id": session['user_id']
    }
    return render_template("success.html", one_user=User.get_one(data))


@app.route('/validateLogin', methods=['POST'])
def login():
    data = { 
        "email" : request.form["email"]
    }
    user_in_db = User.get_one_email(data)
    if not user_in_db:
        flash("The Email Adress is not registered")
        return redirect("/")
    
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        flash("Invalid Password")
        return redirect('/')

    flash('You Are LOGGED IN !!!')
    session['user_id'] = user_in_db.id
    session['email'] = user_in_db.email
    session['route'] = 'login'
    return redirect('/success')

@app.route('/Logout')
def Logout():
    session.clear()
    return redirect('/')




