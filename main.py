from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, SignInForm, CommentForm
from flask_gravatar import Gravatar

from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(
    app=app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CREATE LOGIN MANAGER
login_manager = LoginManager(app)

ADMIN_IDs = [1, 2]


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


# CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship("Comment", backref="blog_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    # posts = relationship("BlogPost", back_populates="author")
    # Alternatively, the relationship.backref option may be used on a single relationship()
    # instead of using relationship.back_populates
    posts = db.relationship("BlogPost",
                            backref="author")  # i.e., if using backref option instead of back_populates option, only need to define relationship in the parent
    comments = db.relationship("Comment", backref="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    blog_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))


db.create_all()


def admin_only(func):
    @wraps(func)
    def inner(*args, **kwargs):
        is_admin = bool(isinstance(current_user, UserMixin) and current_user.id in ADMIN_IDs)
        if is_admin:
            return func(*args, **kwargs)
        else:
            return abort(403)

    return inner


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    print(posts)
    is_admin = bool(isinstance(current_user, UserMixin) and current_user.id in ADMIN_IDs)
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, is_admin=is_admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    registration_form = RegisterForm()
    if registration_form.validate_on_submit():
        new_user = User()
        registration_form.populate_obj(obj=new_user)
        if db.session.query(User).filter_by(email=new_user.email).first():
            flash("You have already registered with that email, login instead!")
            return redirect(url_for("login"))
        new_user.password = generate_password_hash(new_user.password, method="pbkdf2:sha512:8000", salt_length=16)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=registration_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    sign_in_form = SignInForm()

    if sign_in_form.validate_on_submit():
        user = db.session.query(User).filter_by(email=sign_in_form.email.data).first()
        if user:
            check_pwd = check_password_hash(user.password, sign_in_form.password.data)
            if check_pwd:
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password incorrect, please try again.")
        else:
            flash("That email does not exist, please try again.")

    return render_template("login.html", form=sign_in_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    is_admin = bool(isinstance(current_user, UserMixin) and current_user.id in ADMIN_IDs)
    comments = db.session.query(Comment).filter_by(blog_post_id=post_id)
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=comment_form.body.data,
                author_id=current_user.id,
                blog_post_id=post_id
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("User must be logged in to leave a comment.")
            return redirect(url_for("login"))

    db.session.query()
    return render_template("post.html", post=requested_post, is_admin=is_admin,
                           logged_in=current_user.is_authenticated, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            # author_id=current_user.id,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_edit=False, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author_id = current_user.id
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True,
                           logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
