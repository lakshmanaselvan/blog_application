from flask import Flask, render_template, request, flash, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user, login_url


app = Flask(__name__)
app.config['SECRET_KEY'] = "1234567890"
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///blog.db'

db=SQLAlchemy(app)
migrate=Migrate(app,db)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class Register(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(1000), nullable=False)
    email=db.Column(db.String(1000), nullable=False, unique=True)
    password_hash=db.Column(db.String(200))
    date_added=db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return '<Username %r>' % self.username
    
    @property
    def password(self):
        raise AttributeError('Password is not a readable')
    @password.setter
    def password(self,password):
        self.password_hash=generate_password_hash(password)
    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)
    
@login_manager.user_loader
def load_user(user_id):
    return Register.query.get(int(user_id))

class Posts(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String(255))
    author=db.Column(db.String(255))
    slug=db.Column(db.String(255))
    content=db.Column(db.Text)
    date_posted=db.Column(db.DateTime, default=datetime.utcnow)

class RegisterForm(FlaskForm):
    username=StringField("Username", validators=[DataRequired()])
    email=StringField("Email", validators=[DataRequired()])
    password_hash=PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash1', message='Password Must Match!')])
    password_hash1=PasswordField("Confirm_Password", validators=[DataRequired()])
    submit=SubmitField("Submit")

class Login(FlaskForm):
    username=StringField("Username", validators=[DataRequired()])
    password=PasswordField("Password", validators=[DataRequired()])
    submit=SubmitField("Submit")
    
class Post(FlaskForm):
    title=StringField("Title", validators=[DataRequired()])
    content=StringField("Content", validators=[DataRequired()], widget=TextArea())
    author=StringField("Author", validators=[DataRequired()])
    slug=StringField("Slug", validators=[DataRequired()])
    submit=SubmitField("Submit")
    
@app.route('/')
def home():
    return render_template("home.html")

@app.errorhandler(404)
def page_to_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_to_found(e):
    return render_template("500.html"), 500

@app.route('/post', methods=['GET','POST'])
@login_required
def post():
    form=Post()
    if form.validate_on_submit():
        post = Posts(title=form.title.data, content=form.content.data, author=form.author.data, slug=form.slug.data)
        form.title.data=''
        form.content.data=''
        form.author.data=''
        form.slug.data=''
        
        db.session.add(post)
        db.session.commit()
        flash("Blog Post Added Successfully!")
    return render_template("post.html", form=form)

@app.route('/post/view/<int:id>')
def view(id):
    post=Posts.query.get_or_404(id)
    return render_template('view.html', post=post)

@app.route('/post/show')
def show():
    posts=Posts.query.order_by(Posts.date_posted)
    return render_template("show.html", posts=posts)

@app.route('/post/delete/<int:id>')
@login_required
def deletepost(id):
    post_to_delete=Posts.query.get_or_404(id)
    
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash("Blog post was deleted!")
        posts=Posts.query.order_by(Posts.date_posted)
        return render_template("show.html", posts=posts)
    except:
         flash("Whoops!! There was a problem to delete the post-Try Again......!")
         posts=Posts.query.order_by(Posts.date_posted)
         return render_template("show.html", posts=posts)
     
@app.route('/post/edit/<int:id>', methods=['GET','POST'])      
@login_required
def editpost(id):
    post=Posts.query.get_or_404(id)
    form=Post()
    if form.validate_on_submit():
        post.title=form.title.data
        post.author=form.author.data
        post.slug=form.slug.data
        post.content=form.content.data
        db.session.add(post)
        db.session.commit()
        flash("Post has been updated!")
        return redirect(url_for('post', id=post.id))
    form.title.data=post.title
    form.author.data=post.author
    form.slug.data=post.slug
    form.content.data=post.content
    return render_template("editpost.html", form=form)
    
    
@app.route('/details')
def details():
    form=RegisterForm()
    our_users=Register.query.order_by(Register.date_added)
    return render_template("details.html",form=form, our_users=our_users)

@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete=Register.query.get_or_404(id)
    username=None
    form=RegisterForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully")
        our_users=Register.query.order_by(Register.date_added)
        return render_template("details.html",form=form,username=username, our_users=our_users)    
    except:
        flash("Whoops!! There was a problem-Try Again......!")
        return render_template("details.html",form=form,username=username, our_users=our_users)

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = RegisterForm()
    username_to_update = Register.query.get_or_404(id)
    if request.method == "POST":
        username_to_update.name = request.form['username']
        username_to_update.email = request.form['email']
        try:
            db.session.commit()
            flash("User updated successfully")
            return render_template("update.html",form=form, username_to_update=username_to_update)
        except:
            flash("Looks like there was the problem....Try aggin!")
            return render_template("update.html",form=form, username_to_update=username_to_update)
    else:
        return render_template("update.html",form=form, username_to_update=username_to_update)
    

@app.route("/registration", methods=['GET','POST'])
def registration():
    username=None
    form=RegisterForm()
    if form.validate_on_submit():
        user = Register.query.filter_by(email=form.email.data).first()
        if user is None:
            hash_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Register(username=form.username.data, email=form.email.data, password_hash=hash_pw)
            db.session.add(user)
            db.session.commit()
        username=form.username.data
        form.username.data=''
        form.email.data=''
        form.password_hash.data=''
        flash("User Added Successfully")
    return render_template("registration.html", username=username, form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form=Login()
    if form.validate_on_submit():
        user = Register.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash,form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password-Try Again")
        else:
            flash("That user doesn't exist!-Try Again")
    return render_template("login.html", form=form)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash("You were logout Thanks!!")
    return redirect(url_for('login'))
    

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)