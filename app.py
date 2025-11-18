# 1. 必要な道具をインポート
from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
import datetime
from datetime import timedelta # timezone は削除
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import secrets
import bleach
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# --- データベース接続 ---
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///team_board.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_very_secret_key_12345')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインが必要です。'

# --- 2. モデル ---
# ▼▼▼【修正】JST指定を削除し、標準の datetime.datetime.now に戻す ▼▼▼

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False) 
    threads = db.relationship('Thread', backref='author', lazy=True)
    posts = db.relationship('Post', backref='author', lazy=True)

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now) # JST削除
    posts = db.relationship('Post', backref='thread', lazy=True, cascade="all, delete-orphan")

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now) # JST削除
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ShelfConfig(db.Model):
    key = db.Column(db.String(2), primary_key=True) 
    value = db.Column(db.String(2), default='00', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now) # JST削除
    updated_at = db.Column(db.DateTime)

class Invitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(32), unique=True, nullable=False) 

# --- Jinja2 フィルター ---
def urlize_filter(text):
    return bleach.linkify(text)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- 3. ルート（仕事） ---
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/bbs-content')
@login_required
def get_bbs_content():
    all_threads = Thread.query.options(db.joinedload(Thread.author)).order_by(Thread.timestamp.desc()).all()
    
    # ▼▼▼【修正】ここも JST を削除 ▼▼▼
    now = datetime.datetime.now() 
    three_days_ago = now - timedelta(days=3)
    
    html = render_template('_bbs_content.html', threads=all_threads, three_days_ago=three_days_ago)
    response = make_response(html)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/todo-content')
@login_required
def get_shelf_display():
    shelf_data = ShelfConfig.query.all()
    
    # ▼▼▼【修正】ここも JST を削除 ▼▼▼
    now = datetime.datetime.now()
    three_days_ago = now - timedelta(days=3)
    
    html = render_template('_todo_content.html', shelf_data=shelf_data, three_days_ago=three_days_ago)
    response = make_response(html)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/new')
@login_required
def new_thread():
    return render_template('new_thread.html')

@app.route('/create', methods=['POST'])
@login_required
def create_thread():
    title_from_form = request.form['title']
    new_thread = Thread(title=title_from_form, user_id=current_user.id) 
    db.session.add(new_thread)
    db.session.commit()
    return redirect(url_for('dashboard')) 

@app.route('/thread/<int:thread_id>', methods=['GET', 'POST'])
def thread_detail(thread_id):
    thread_from_db = Thread.query.options(
        db.joinedload(Thread.posts).joinedload(Post.author)
    ).get_or_404(thread_id)
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('投稿するにはログインが必要です。', 'error')
            return redirect(url_for('login'))
        content_from_form = request.form['content']
        new_post = Post(content=content_from_form, 
                        thread_id=thread_from_db.id, 
                        user_id=current_user.id) 
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('thread_detail', thread_id=thread_from_db.id))
    return render_template('thread_detail.html', thread=thread_from_db)

@app.route('/post/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post_to_delete = db.session.get(Post, post_id)
    if not post_to_delete:
        flash('投稿が見つかりません。', 'error')
        return redirect(url_for('dashboard'))
    if not current_user.is_admin:
        flash('投稿を削除できるのはアドミンだけです。', 'error')
        return redirect(url_for('thread_detail', thread_id=post_to_delete.thread_id))
    db.session.delete(post_to_delete)
    db.session.commit()
    flash('投稿を削除しました。', 'success')
    return redirect(url_for('thread_detail', thread_id=post_to_delete.thread_id))

@app.route('/thread/delete/<int:thread_id>', methods=['POST'])
@login_required
def delete_thread(thread_id):
    thread_to_delete = db.session.get(Thread, thread_id)
    if not thread_to_delete:
        flash('スレッドが見つかりません。', 'error')
        return redirect(url_for('dashboard'))
    if not current_user.is_admin:
        flash('スレッドを削除できるのはアドミンだけです。', 'error')
        return redirect(url_for('dashboard'))
    db.session.delete(thread_to_delete)
    db.session.commit()
    flash('スレッドを削除しました。', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/invite', methods=['GET', 'POST'])
@login_required
def admin_invite():
    if not current_user.is_admin:
        flash('アドミン専用ページです。', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        new_key_str = secrets.token_hex(16)
        new_invitation = Invitation(key=new_key_str)
        db.session.add(new_invitation)
        db.session.commit()
        flash(f'新しい招待キーを発行しました: {new_key_str}', 'success')
        return redirect(url_for('admin_invite'))
    return render_template('admin_invite.html')

@app.route('/claim-invite', methods=['GET', 'POST'])
def claim_invite():
    if request.method == 'POST':
        key_from_form = request.form['key']
        username = request.form['username']
        password = request.form['password']
        invitation = Invitation.query.filter_by(key=key_from_form).first()
        if not invitation:
            flash('招待キーが正しくありません。', 'error')
            return redirect(url_for('claim_invite'))
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('そのユーザー名は既に使用されています。', 'error')
            return redirect(url_for('claim_invite'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.delete(invitation)
        db.session.commit()
        flash('登録が完了しました。ログインしてください。', 'success')
        return redirect(url_for('login'))
    return render_template('claim_invite.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard')) 
        else:
            flash('ユーザー名またはパスワードが正しくありません。', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/settings')
@login_required
def settings_page():
    return render_template('settings_page.html')

@app.route('/settings/shelf', methods=['GET', 'POST'])
@login_required
def settings_shelf():
    if request.method == 'POST':
        data = request.form
        try:
            for prefix, suffix in data.items():
                if not (suffix.isdigit() and 0 <= int(suffix) <= 99):
                    flash(f'「{prefix}」の設定値が無効です。00から99までの数字を入力してください。', 'error')
                    return redirect(url_for('settings_shelf'))
                formatted_suffix = suffix.zfill(2)
                config = ShelfConfig.query.filter_by(key=prefix).first()
                if config:
                    config.value = formatted_suffix
                    # ▼▼▼【修正】JST削除 ▼▼▼
                    config.updated_at = datetime.datetime.now() 
                else:
                    db.session.add(ShelfConfig(key=prefix, value=formatted_suffix))
            db.session.commit()
            flash('棚番号の設定を保存しました。', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'保存中にエラーが発生しました: {e}', 'error')
        return redirect(url_for('settings_shelf'))
    shelf_data = ShelfConfig.query.all()
    return render_template('settings_shelf.html', shelf_data=shelf_data)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if not bcrypt.check_password_hash(current_user.password_hash, old_password):
            flash('古いパスワードが正しくありません。', 'error')
            return redirect(url_for('change_password'))
        if new_password != confirm_password:
            flash('新しいパスワードが確認用と一致しません。', 'error')
            return redirect(url_for('change_password'))
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password_hash = hashed_password
        db.session.commit()
        flash('パスワードが正常に変更されました。', 'success')
        return redirect(url_for('dashboard')) 
    return render_template('change_password.html')

app.jinja_env.filters['urlize'] = urlize_filter

with app.app_context():
    db.create_all() 
    if not ShelfConfig.query.first():
        db.session.add(ShelfConfig(key='11', value='00'))
        db.session.add(ShelfConfig(key='12', value='00'))
        db.session.add(ShelfConfig(key='13', value='00'))
        db.session.commit()
    if not User.query.filter_by(username='admin').first():
        print(" * 初代アドミンを作成します...")
        hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
        admin_user = User(username='admin', 
                          password_hash=hashed_password, 
                          is_admin=True) 
        db.session.add(admin_user)
        db.session.commit()
        print(" * ユーザー名: admin")
        print(" * パスワード: password")

if __name__ == '__main__':
    app.run(debug=True)　
