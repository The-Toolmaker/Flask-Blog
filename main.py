from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("://", "ql://", 1)
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///blog.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# configure relationship one to many
Base = declarative_base()


# CONFIGURE TABLES
# Create a user data table with password hashing
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")

    # This will act like a list o comments objects attached to each User
    # the "author" refers to the author property in the comments class
    comments = relationship("Comments", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the table name of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts' property in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comments", back_populates="parent_post")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    # Create a Foreign Key
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # create a reference to User object, the "comments" refers to the comment's property in User class
    author = relationship("User", back_populates="comments")

    # Create a Foreign Key
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # create a reference to BlogPosts objects
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()  # set up db


# Create a login manager
@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))


# Create a login required decorator
# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # check if the register form were submitted
    form = RegisterForm()
    if form.validate_on_submit():
        # check if the email already exists in db, since it's unique we can check for first
        if User.query.filter_by(email=form.email.data).first():
            # Flash a message and redirect user to register url
            flash("User already exists")
        else:  # if unique, then save new user in database
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data,
                                                method='pbkdf2:sha256',
                                                salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            # after committed, redirect user to login page and flash a success message
            flash("Your user was successfully registered, please login")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # instantiate a login form
    if form.validate_on_submit():  # if login form is submitted
        email = form.email.data  # get email submitted as form
        user = User.query.filter_by(email=email).first()  # get user in db
        if user:  # check if user exists
            sub_password = form.password.data  # get submitted password
            reg_password = user.password  # get user password in db
            if check_password_hash(reg_password, sub_password):  # check if passwords matches
                login_user(user)  # login if successful
                return redirect(url_for('get_all_posts'))  # redirect to home page
            else:  # if password is incorrect, then redirect to login page and flash a new message
                flash("Password incorrect, try login again!")
                return redirect(url_for('login'))
        else:  # if email does not exist in db, then flash a message and redirect
            flash("This email is not registered!")
            return redirect(url_for('register'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()  # logout user
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comments()
            new_comment.text = form.comment.data
            new_comment.author = current_user
            new_comment.parent_post = requested_post
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("Login to comment")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


# @login_required
@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# @login_required
@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


# @login_required
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
