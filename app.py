from distutils.sysconfig import customize_compiler
from os.path import curdir

from Tools.scripts.make_ctype import method
from flask import Flask, render_template, url_for, session, flash
from flask_wtf import FlaskForm
from werkzeug.utils import redirect
from wtforms import StringField
from wtforms.fields.simple import PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL

app = Flask(__name__)

# mysql configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM user WHERE email=%s',(field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError("email already taken..")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")





@app.route('/', methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # store data in database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO user (name,email,password) VALUES (%s,%s,%s)", (name, email, hash_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # store data in database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM user WHERE email=%s",(email,))
        user=cursor.fetchone()
        cursor.close()

        if user and bcrypt.checkpw(password.encode('utf-8'),user[3].encode('utf-8')):
            session['user_id']=user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed")
            return redirect(url_for('login'))


    return render_template('login.html',form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM user WHERE id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return render_template('dashboard.html',user=user)

    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash(" you have been logged out successfully. ")
    return redirect('login')


if __name__ == '__main__':
    app.run(debug=True)
