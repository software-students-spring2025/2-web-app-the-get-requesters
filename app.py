from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import pymongo
import os
from dotenv import load_dotenv
from bson.objectid import ObjectId
from datetime import datetime, timezone
import re # just for search

load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/')
app.secret_key = os.getenv("SECRET_KEY")

bcrypt = Bcrypt(app)

connection = pymongo.MongoClient(os.getenv("MONGODB_URI"), tls=True, tlsAllowInvalidCertificates=True)
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
    if current_user.is_authenticated:
        return redirect(url_for('home'))
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
        print(event)
        if isinstance(event['event_date'], datetime):
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
    members = list(users_collection.find({'username': {'$ne': current_user.username}}))
    if request.method == 'POST':
        group_name = request.form['group_name']
        if groups_collection.find_one({'group_name': group_name}):
             flash("Group name is already taken. Please pick another", "danger")
        members = [current_user.username] + request.form.getlist('username')
        new_group = groups_collection.insert_one({'owner': current_user.username, 'group_name': group_name, 'members': members})
        return redirect(url_for('groups'))
        
    return render_template("create_group.html", members=members)

@app.route('/groups', methods=['GET', 'POST'])
@login_required
def groups():
    groups = list(groups_collection.find({'members': current_user.username}))
    results = []
    if request.method == 'POST':
        search_term = request.form['search_term'].lower()
        results = [group for group in groups if search_term.lower() == group.lower()]
    return render_template("groups.html", groups=groups, results=results)


@app.route('/group/<group_name>', methods=['GET', 'POST'])
@login_required
def group_details(group_name):
    if request.method == 'POST':
        if 'delete_group' in request.form:
            groups_collection.delete_one({"group_name": request.form['group_name']})
        elif 'edit_group' in request.form:
            new_members = request.form.getlist('username')
            print(request.form)
            update_operation = { '$set' : 
                { 'members' : new_members}
            }
            groups_collection.update_one({"group_name": request.form['group_name']}, update_operation)
            
        return redirect(url_for('groups'))

    group = db.groups.find_one({"group_name": group_name})
    all_members = users_collection.find({})
    
    if not group or group["owner"] != current_user.username:
        flash("You are not authorized to view this group.", "danger")
        return redirect(url_for('groups'))

    return render_template("group_details.html", group=group, members=all_members)

@app.route('/profile')
@login_required
def profile():
    username = current_user.username
    created_groups = list(groups_collection.find({"owner": username}))
    joined_groups = list(groups_collection.find({"members": username, "owner": {"$ne": username}}))

    return render_template("profile.html", created_groups=created_groups, joined_groups=joined_groups)

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        try:
            creator = current_user.username
            event_name = request.form['event_name']
            description = request.form.get("description")
            event_date = request.form.get("event_date")
            date_obj = datetime.strptime(event_date, "%Y-%m-%d")
            invitees = [current_user.username] + request.form.getlist('username')
            invited_groups = request.form.getlist('group_name')
            
            db.events.insert_one({
                "creator": creator,
                "event_name": event_name,
                "description": description,
                "event_date": date_obj.strftime("%B %d, %Y"),
                "attending": [],
                "invitees": invitees,
                "invited_groups": invited_groups
            })
            flash("Event created successfully!", "success")
            return redirect(url_for('home'))
    
        # event_name = request.form.get("event_name")
        # event_date = request.form.get("event_date")
        # description = request.form.get("description")
        # invitees = request.form.get("invitees").split(",")
        # event_creator = current_user.username
        # print(event_date)
        # try:
        #     date_obj = datetime.strptime(event_date,"%Y-%m-%d")

        #     db.events.insert_one({
        #         "event_name": event_name,
        #         "event_date": date_obj.strftime("%B %d, %Y"),
        #         "description": description,
        #         "invitees":[user.strip() for user in invitees],
        #         "creator": event_creator
        #     })

        #     flash("Event created successfully!", "success")
        #     return redirect(url_for('home'))
        
        except Exception as e:
            flash(f"Error creating event: {str(e)}", "danger")
            return redirect(url_for('create_event'))
    
    members = list(users_collection.find({'username': {'$ne': current_user.username}}))
    groups = list(groups_collection.find())
    return render_template("create_event.html", members=members, groups=groups)

@app.route('/delete_event/<event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    event = db.events.find_one({"_id": ObjectId(event_id)})
    
    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for('home'))
    
    if event['creator'] != current_user.username:
        flash("You can only delete events you created.", "danger")
        return redirect(url_for('home'))
    
    events_collection.delete_one({"_id": ObjectId(event_id)})
    
    flash(f"Event '{event_id}' has been deleted.", "success")
    return redirect(url_for('home'))

@app.route('/leave_event/<event_id>', methods=['POST'])
@login_required
def leave_event(event_id):
    event = db.events.find_one({"_id": ObjectId(event_id)})
    
    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for('home'))
    
    if current_user.username not in event.get('invitees', []):
        flash("You are not a participant in this event.", "danger")
        return redirect(url_for('home'))
    
    if event['creator'] == current_user.username:
        flash("As the creator, you can't leave your own event. You can delete it instead.", "warning")
        return redirect(url_for('home'))
    
    events_collection.update_one(
        {"_id": ObjectId(event_id)},
        {"$pull": {"invitees": current_user.username}}
    )
    
    flash(f"You have left the event '{event_id}'.", "success")
    return redirect(url_for('home'))

@app.route('/event/<event_id>')
@login_required
def your_event_details(event_id):
    """
    Test data

    event = {
        "event_id": "test",
        "owner": "lana",
        "date": 1740897357,
        "invitees": ["andrew", "samantha", "lana", "jack"]
    }
    comments = [
        {
            "user": "andrew",
            "text": "nice!"
        },
        {
            "user": "lana",
            "text": "thanks!"
        }
    ]
    """
    event = db.events.find_one({"_id": ObjectId(event_id)})

    if not event or event["creator"] != current_user.username:
        flash("You are not authorized to view this event.", "danger")
        return redirect(url_for('home'))

    # event["date_display"] = datetime.fromtimestamp(event["event_date"], tz=timezone.utc).strftime('%B %d, %Y')
    comments = list(db.comments.find({"event_id": event_id}))
    
    return render_template("your_event_details.html", event=event, comments=comments)

@app.route('/edit_event/<event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    if request.method == 'POST':
        try:
            creator = current_user.username
            event_name = request.form['event_name']
            description = request.form.get("description")
            event_date = request.form.get("event_date")
            date_obj = datetime.strptime(event_date, "%Y-%m-%d")
            invitees = [current_user.username] + request.form.getlist('username')
            invited_groups = request.form.getlist('group_name')
            
            update_fields = {
                "creator": creator,
                "event_name": event_name,
                "description": description,
                "event_date": date_obj.strftime("%B %d, %Y"),
                "invitees": invitees,
                "invited_groups": invited_groups
            }
            db.events.update_one(
                {"_id": ObjectId(event_id)},
                {"$set": update_fields}
            )

            flash("Event updated successfully!", "success")
            return redirect(url_for('home'))
        
        except Exception as e:
            flash(f"Error creating event: {str(e)}", "danger")
            return redirect(url_for('home'))
        
    event = db.events.find_one({"_id": ObjectId(event_id)})
    members = list(users_collection.find({'username': {'$ne': current_user.username}}))
    groups = list(groups_collection.find())
    return render_template("edit_event.html", event=event, members=members, groups=groups)

@app.route('/rsvp/<event_id>', methods=['POST'])
@login_required
def rsvp_event(event_id):
    event = events_collection.find_one({"_id": ObjectId(event_id)})

    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for('home'))
    
    if current_user.username in event.get("attending", []):
        flash("You have already RSVP'd to this event.", "info")
    else:
        if current_user.username not in event.get("invitees", []):
            flash("You are not invited to this event.", "danger")
            return redirect(url_for('home'))
        
        events_collection.update_one(
            {"_id": ObjectId(event_id)},
            {"$addToSet": {"attending": current_user.username}}
        )
        flash("You have successfully RSVP'd to the event!", "success")
    
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5001), debug=True)