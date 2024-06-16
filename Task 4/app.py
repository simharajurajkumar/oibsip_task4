
from flask import Flask, render_template, request, redirect, url_for, session, flash
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key in production

# Simple in-memory storage for user data
users = {}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            flash('Username already exists. Please choose a different one.', 'error')
        else:
            # Hash the password before storing
            hashed_password = sha256_crypt.hash(password)
            users[username] = hashed_password
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and sha256_crypt.verify(password, users[username]):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('secured'))

        flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')

@app.route('/secured')
def secured():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    return render_template('secured.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
