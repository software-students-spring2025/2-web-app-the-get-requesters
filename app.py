from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import pymongo
import os
from dotenv import load_dotenv
from bson.objectid import ObjectId
from datetime import datetime

load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='public', static_url_path='/')
app.secret_key = os.getenv("SECRET_KEY")

bcrypt = Bcrypt(app)

connection = pymongo.MongoClient(os.getenv("MONGODB_URI"))
db = connection[os.getenv("DB_NAME")]
users_collection = db["users"]
groups_collection = db["groups"]
events_collection = db["events"]

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
login_manager.login_message = ''

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
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = users_collection.find_one({"username": username})
        
        if user_data:
            if bcrypt.check_password_hash(user_data["password"], password):
                user = User(user_data)
                login_user(user)
                
                next_page = request.args.get('next')
                return redirect(next_page if next_page else url_for('home'))
            else:
                flash('Invalid password. Please try again.', 'danger')
        else:
            flash('User does not exist. Please try again.', 'danger')
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
        else:
            flash('Username already exists. Please choose a different one.', 'danger')

    return render_template("register.html")

@app.route('/home')
@login_required
def home():
    username = current_user.username
    created_events = list(events_collection.find({"creator": username}))
    joined_events = list(events_collection.find({"attending": username, "creator": {"$ne": username}}))

    for event in created_events + joined_events:
        if isinstance(event["event_date"], datetime):
            event["event_date"] = event["event_date"].strftime('%B %d, %Y')

    return render_template("home.html", created_events=created_events, joined_events=joined_events)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        group_name = request.form['group_name']
        members = [member.strip() for member in request.form['members'].split(',') if member.strip()]
        members = list(set(members))

        existing_group = groups_collection.find_one({"group_name": group_name})
        if existing_group:
            flash(f"This group already exists", "warning")
            return redirect(url_for('create_group'))

        valid_users = {user["username"] for user in users_collection.find({"username": {"$in": members}})}
        invalid_users = set(members) - valid_users
        members = list(valid_users)
        if invalid_users:
            flash(f"The following users were not found: {', '.join(invalid_users)}", "warning")
            return redirect(url_for('create_group'))

        new_group = groups_collection.insert_one({'owner': current_user.username, 'group_name': group_name, 'members': list(members)})
        return redirect(url_for('profile'))
        
    return render_template("create_group.html")

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        description = request.form['description']
        group = request.form['group_name']

        try:
            event_date = datetime.strptime(event_date, "%Y-%m-%d")
        except ValueError:
            flash("Invalid date format!", "danger")
            return redirect(url_for('create_event'))
        
        group = groups_collection.find_one({"group_name": group})
        if not group:
            flash("Group Not Found", "warning")
            return redirect(url_for("create_event"))
        attending = group["members"]

        new_event = events_collection.insert_one({
                                                'creator': current_user.username,
                                                'event_name': event_name,
                                                'description': description,
                                                'event_date': event_date,
                                                'attending': list(attending),
                                                'group_name': group["group_name"]
                                                })
        return redirect(url_for('home'))
        
    return render_template("create_event.html")

@app.route('/groups')
@login_required
def groups():
    groups = groups_collection.find({'members': 'member3'})
    return render_template("groups.html", groups=groups)

@app.route('/profile')
@login_required
def profile():
    username = current_user.username
    created_groups = list(groups_collection.find({"owner": username}))
    joined_groups = list(groups_collection.find({"members": username, "owner": {"$ne": username}}))

    return render_template("profile.html", created_groups=created_groups, joined_groups=joined_groups)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5001), debug=False)