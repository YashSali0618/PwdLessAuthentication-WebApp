################################# Essential Imports #################################
import os
import secrets
import uuid
import pyotp 
import qrcode
from io import * 
from PIL import Image
from flask import *
from pwdlapp import app, db, bcrypt
from pwdlapp.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, OTPForm, SecretForm
from pwdlapp.models import User, Post, Encfile
from flask_login import login_user, current_user, logout_user, login_required
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes


################################# Home Route #################################
@app.route("/")
@app.route("/home")
def home():
    posts = Post.query.all()
    return render_template('home.html', posts=posts)


################################# About Route #################################
@app.route("/about")
def about():
    return render_template('about.html', title='About')


################################# Register Route #################################
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


################################# LogIn Route #################################
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


################################# Logout Route #################################
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


################################# Account Route #################################
@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)


################################# New Post Route #################################
@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post',
                           form=form, legend='New Post')


################################# Post ID Route #################################
@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)


################################# Update Post Route #################################
@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Update Post',
                           form=form, legend='Update Post')


################################# Delete Post Route #################################
@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))


################################# Encryption Route #################################
###################### Using ChaCha20 Stream Cipher Algorithm ######################
@app.route("/enc", methods=['GET', 'POST'])
@login_required
def enc():
    key = get_random_bytes(32)
    uid = uuid.uuid4().hex
    if request.method == 'POST':
        file = request.files['file']
        data = file.read()
        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.encrypt(data)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ciphertext).decode('utf-8')
        result = nonce + ct
        user = current_user.username
        file_name = file.filename
        encfile = Encfile( user = user, key = key, uid = uid, result = result, file_name = file_name)
        db.session.add(encfile)
        db.session.commit()
        flash('Your file has been successfully Encrypted!', 'success')
        flash('Your Unique ID to Access ' + file.filename + ' is ' + uid, 'success')
    return render_template('encfile.html', title='Encrypt File')
        

################################# Decryption Route #################################
###################### Using ChaCha20 Stream Cipher Algorithm ######################
@app.route("/dec", methods=['GET', 'POST'])
@login_required
def dec():
    if request.method == 'POST':
        user_key = request.form['uid']
        encfile = Encfile.query.filter_by(uid = user_key).first()
        if current_user.username != encfile.user:
            abort(403)
        key = encfile.key
        result = encfile.result
        try:
            length = len(result)
            iv = result[:12]
            iv = b64decode(iv)
            nonce = iv
            ciphertext = result[12:length]
            ciphertext = b64decode(ciphertext)
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt(ciphertext)
            f = decrypted
            n = encfile.file_name
            flash('Your file ' + n + ' is successfully Decrypted and Downloaded!', "success")
            with open (n, 'wb+') as f:
                f.write(decrypted)
                f.close
        except (ValueError,KeyError):
            print ('Decryption Failed')
    return render_template('decfile.html', title='Decrypt File')


################################# OTP Route #################################
@app.route("/otp", methods=['GET', 'POST'])
def otp():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = OTPForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        secret = user.secret
        otp = form.otp.data
        if pyotp.TOTP(secret).verify(otp):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and OTP', 'danger')
    return render_template('login_otp.html', title='OTP Login', form=form)


################################# Secret Token Route #################################
@app.route("/secret", methods=['GET', 'POST'])
def secret():
    secret = pyotp.random_base32()
    form = SecretForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            user.secret = secret
            db.session.commit()
            sec =pyotp.TOTP(secret)
            qr = qrcode.make(sec.provisioning_uri(user.email))
            img = BytesIO()
            qr.save(img)
            img.seek(0)
            flash('Your secret is: ' + secret)
            return send_file(img, mimetype="image/png")
        else:
            flash('Authentication failed. Please check email and password', 'danger')
    return render_template('secret.html', title='Secret Key', form=form)