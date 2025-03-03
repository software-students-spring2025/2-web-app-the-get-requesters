from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import pymongo
import os
from dotenv import load_dotenv
from bson.objectid import ObjectId

load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/')
app.secret_key = os.getenv("SECRET_KEY")

bcrypt = Bcrypt(app)

connection = pymongo.MongoClient(os.getenv("MONGODB_URI"))
db = connection[os.getenv("DB_NAME")]
users_collection = db["users"]

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.password_hash = user_data["password"]
    
    def get_id(self):
        return self.id
    
    @staticmethod
    def validate_login(password_hash, password):
        return bcrypt.check_password_hash(password_hash, password)
    
@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user_data:
        return None
    return User(user_data)

@app.route('/')
def index():
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = users_collection.find_one({"username": username})
        
        if user_data and bcrypt.check_password_hash(user_data["password"], password):
            user = User(user_data)
            login_user(user)
            
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('home'))
    
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        existing_user = users_collection.find_one({"username": username})
        
        if existing_user is None:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            users_collection.insert_one({
                "username": username,
                "password": hashed_password
            })
            return redirect(url_for('login'))

    return render_template("register.html")

@app.route('/home')
def home():
    return render_template("home.html")

@app.route('/profile')
def profile():
    return render_template("profile.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5001), debug=False)