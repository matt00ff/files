import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import random
from string import ascii_uppercase
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = "some_secret_key"

# Настраиваем SQLite
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mydatabase.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)

# Папка для аватаров
AVATAR_FOLDER = os.path.join(app.root_path, "static", "avatars")
os.makedirs(AVATAR_FOLDER, exist_ok=True)

# -----------------------------
# Модель пользователя (SQLAlchemy)
# -----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(120), default = "user")
    is_banned = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200), default="default.png")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

# Создаём таблицы (если не существуют)
with app.app_context():
    db.create_all()

# Контекстный процессор для передачи текущего пользователя в шаблоны
@app.context_processor
def inject_user():
    if session.get("username"):
        user = User.query.filter_by(username=session["username"]).first()
        return dict(current_user=user)
    return {}

# -----------------------------
# Параметры чатов
# -----------------------------
chats_db = {}  # {chat_name: {"members": set([...]), "messages": [...]}}

MAX_CHATS = 5
MAX_MEMBERS_PER_CHAT = 3

def generate_chat_name(length=4):
    """Генерация случайного имени (кода) для чата."""
    while True:
        code = "".join(random.choice(ascii_uppercase) for _ in range(length))
        if code not in chats_db:
            return code

def broadcast_chats_update():
    """Обновляет список чатов у всех пользователей в разделе 'Чаты'."""
    existing_chats = [
        (chat_name, len(chats_db[chat_name]["members"]))
        for chat_name in chats_db
    ]
    socketio.emit("chat_list_updated", {"chats": existing_chats}, room="chats_room")

BAD_WORDS = ["Сука", "Пизда", "Бля"]

def filter_bad_words(text):
    """Заменяет нецензурные слова звездочками."""
    for word in BAD_WORDS:
        text = text.replace(word, "***")
    return text

# -----------------------------
# Маршруты
# -----------------------------
@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("chats"))
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return render_template("index.html", reg_error="Введите логин и пароль")

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return render_template("index.html", reg_error="Такой логин уже существует. Войдите.")

    # Если это первый пользователь, делаем его админом
    role = "admin" if User.query.count() == 0 else "user"

    # Передаём роль при создании пользователя
    new_user = User(username=username, password=password, role=role)
    db.session.add(new_user)
    db.session.commit()

    session["username"] = username
    session["role"] = role

    return redirect(url_for("chats"))

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or user.password != password:
        return render_template("index.html", login_error="Неверный логин или пароль.")

    session["username"] = username
    session["role"] = user.role
    return redirect(url_for("chats"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/chats")
def chats():
    if not session.get("username"):
        return redirect(url_for("index"))

    existing_chats = [(cn, len(chats_db[cn]["members"])) for cn in chats_db]
    return render_template("chats.html", chats=existing_chats, max_chats=MAX_CHATS, max_members=MAX_MEMBERS_PER_CHAT)

@app.route("/create_chat", methods=["POST"])
def create_chat():
    if not session.get("username") or len(chats_db) >= MAX_CHATS:
        return redirect(url_for("chats"))

    chat_name = request.form.get("chat_name") or generate_chat_name()
    if chat_name in chats_db:
        return redirect(url_for("chats"))

    chats_db[chat_name] = {"members": set(), "messages": []}
    broadcast_chats_update()
    return redirect(url_for("chats"))

@app.route("/join_chat/<chat_name>")
def join_chat(chat_name):
    if not session.get("username") or chat_name not in chats_db:
        return redirect(url_for("chats"))

    if len(chats_db[chat_name]["members"]) >= MAX_MEMBERS_PER_CHAT:
        return redirect(url_for("chats"))

    chats_db[chat_name]["members"].add(session["username"])
    session["room"] = chat_name
    broadcast_chats_update()

    return redirect(url_for("room", chat_name=chat_name))

@app.route("/room/<chat_name>")
def room(chat_name):
    if not session.get("username") or chat_name not in chats_db:
        return redirect(url_for("chats"))

    messages = chats_db[chat_name]["messages"]
    return render_template("room.html", code=chat_name, messages=messages)

@app.route("/leave_chat/<chat_name>")
def leave_chat(chat_name):
    username = session.get("username")
    if not username or chat_name not in chats_db:
        return redirect(url_for("chats"))

    chats_db[chat_name]["members"].discard(username)
    if not chats_db[chat_name]["members"]:
        del chats_db[chat_name]

    session.pop("room", None)
    broadcast_chats_update()
    return redirect(url_for("chats"))

@app.route("/delete_chat/<chat_name>", methods=["POST"])
def delete_chat(chat_name):
    """Удаление пустого чата вручную."""
    if chat_name in chats_db and len(chats_db[chat_name]["members"]) == 0:
        del chats_db[chat_name]
        broadcast_chats_update()
    return redirect(url_for("chats"))

@app.route("/admin")
def admin_panel():
    if session.get("role") != "admin":
        return redirect(url_for("chats"))  # Только админы могут зайти
    return render_template("admin.html")

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not session.get("username"):
        return redirect(url_for("index"))

    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        return redirect(url_for("index"))

    if request.method == "POST":
        # Если нажата кнопка удаления аватарки
        if "delete_avatar" in request.form:
            user.avatar = "default.png"
            db.session.commit()
            flash("Аватар удалён!")
            return redirect(url_for("profile"))

        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("password", "").strip()
        avatar_file = request.files.get("avatar")

        # Изменение логина (с проверкой уникальности)
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash("Логин уже занят. Выберите другой.")
            else:
                user.username = new_username
                session["username"] = new_username

        # Изменение пароля
        if new_password:
            user.password = new_password

        # Загрузка нового аватара
        if avatar_file and avatar_file.filename:
            filename = secure_filename(avatar_file.filename)
            unique_filename = f"{random.randint(1000,9999)}_{filename}"
            avatar_path = os.path.join(AVATAR_FOLDER, unique_filename)
            avatar_file.save(avatar_path)
            user.avatar = unique_filename

        db.session.commit()
        flash("Профиль обновлён!")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)

# -----------------------------
# WebSocket события
# -----------------------------
@socketio.on("join_room")
def handle_join_room(data):
    """Пользователь подключается к комнате."""
    room = data.get("room")
    username = session.get("username")

    if not room or not username or room not in chats_db:
        return

    join_room(room)
    print(f"[DEBUG] {username} вошел в комнату {room}")

    # Отправляем историю сообщений
    emit("message_history", {"messages": chats_db[room]["messages"]}, to=request.sid)

    # Отправляем уведомление в чат
    content = {"name": "Система", "message": f"{username} вошел в чат.", "timestamp": datetime.now().strftime("%H:%M:%S")}
    chats_db[room]["messages"].append(content)
    send(content, to=room)

message_store = {}  # {message_id: {"name": username, "message": текст, "timestamp": datetime}}

@socketio.on("message")
def handle_message(data):
    room = session.get("room")
    username = session.get("username")

    if not room or not username or room not in chats_db:
        return

    # Проверка бана через БД
    user = User.query.filter_by(username=username).first()
    if user and user.is_banned:
        return  # Забаненный пользователь не может отправлять сообщения

    # Фильтрация нецензурных слов и обработка сообщения
    filtered_message = filter_bad_words(data["data"])
    is_quote = filtered_message.startswith("> @")
    message_id = str(len(message_store) + 1)
    timestamp = datetime.now().strftime("%H:%M:%S")

    message_store[message_id] = {
        "name": username,
        "message": filtered_message,
        "timestamp": datetime.now(),
    }

    content = {
        "id": message_id,
        "name": username,
        "message": filtered_message,
        "timestamp": timestamp,
        "isOwn": True,
        "isQuote": is_quote
    }

    chats_db[room]["messages"].append(content)
    send(content, to=room)


@socketio.on("edit_message")
def edit_message(data):
    message_id = data["id"]
    new_message = data["newMessage"]

    if message_id in message_store:
        message_data = message_store[message_id]
        time_diff = datetime.now() - message_data["timestamp"]

        if time_diff < timedelta(minutes=10):  # Можно редактировать в течение 10 минут
            message_data["message"] = new_message
            emit("update_message", {"id": message_id, "newMessage": new_message}, broadcast=True)

@socketio.on("delete_message")
def delete_message(data):
    message_id = data["id"]
    
    if message_id in message_store:
        del message_store[message_id]
        emit("remove_message", {"id": message_id}, broadcast=True)

online_users = set()
@socketio.on("connect")
def handle_connect():
    username = session.get("username")
    if username:
        online_users.add(username)
        # Рассылаем обновлённый список онлайн-пользователей
        socketio.emit("update_user_list", {"users": list(online_users)})

@socketio.on("disconnect")
def on_disconnect():
    """Отключение пользователя."""
    room = session.get("room")
    username = session.get("username")

    # Удаляем пользователя из списка онлайн
    if username in online_users:
        online_users.remove(username)
        # Рассылаем обновлённый список всем клиентам
        socketio.emit("update_user_list", {"users": list(online_users)})

    if room and username and room in chats_db:
        # Отправляем системное сообщение, что пользователь вышел
        content = {
            "name": "Система",
            "message": f"{username} вышел из чата.",
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        send(content, to=room)
        chats_db[room]["members"].discard(username)
        if not chats_db[room]["members"]:
            del chats_db[room]

    session.pop("room", None)
    broadcast_chats_update()

@socketio.on("join_chats_page")
def on_join_chats_page():
    """Пользователь открыл страницу 'Чаты' -> добавляем в 'chats_room'."""
    join_room("chats_room")
    existing_chats = [
        (chat_name, len(chats_db[chat_name]["members"]))
        for chat_name in chats_db
    ]
    emit("chat_list_updated", {"chats": existing_chats}, to=request.sid)

@socketio.on("voice_message")
def handle_voice_message(data):
    """Обрабатывает и передает голосовые сообщения."""
    room = session.get("room")
    if room:
        emit("voice_message", {"data": data["data"]}, to=room)

@socketio.on("file_upload")
def handle_file_upload(data):
    """Обрабатывает отправку файлов и передает их в чат."""
    room = session.get("room")
    if room:
        emit("file_message", {"filename": data["filename"], "data": data["data"]}, to=room)

banned_users = set()

@socketio.on("ban_user")
def ban_user(data):
    if session.get("role") != "admin":
        return
    username = data["username"]
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_banned = True
        db.session.commit()
        emit("user_banned", {"username": username}, broadcast=True)

@socketio.on("unban_user")
def unban_user(data):
    if session.get("role") != "admin":
        return
    username = data["username"]
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_banned = False
        db.session.commit()
        emit("user_unbanned", {"username": username}, broadcast=True)

@socketio.on("grant_admin")
def grant_admin(data):
    """Выдача прав администратора"""
    if session.get("role") != "admin":
        return
    
    username = data["username"]
    user = User.query.filter_by(username=username).first()
    if user:
        user.role = "admin"
        db.session.commit()
        emit("admin_granted", {"username": username}, broadcast=True)

@socketio.on("revoke_admin")
def revoke_admin(data):
    """Снимает права администратора у пользователя"""
    # Только администратор может снимать права у других
    if session.get("role") != "admin":
        return

    username = data["username"]
    user = User.query.filter_by(username=username).first()
    if user and user.role == "admin":
        # Запрещаем админу забирать себе права, если это не требуется
        if user.username == session.get("username"):
            return
        user.role = "user"
        db.session.commit()
        emit("admin_revoked", {"username": username}, broadcast=True)

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
