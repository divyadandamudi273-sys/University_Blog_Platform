import datetime
import re
import os

from bson import ObjectId
from flask import request, Flask, render_template, redirect, session
import pymongo
import bcrypt
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

# ---------- MongoDB setup ----------
my_client = pymongo.MongoClient("mongodb://localhost:27017")
my_database = my_client["university_blog"]

room_owner_collection = my_database["room_owner"]
member_collection = my_database["member"]
admin_collection = my_database["admin"]
room_categories_collection = my_database["room_categories"]
room_collection = my_database["room"]
post_collection = my_database["post"]
polls_collection = my_database["polls"]

# ---------- Flask / file paths ----------
app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
PROFILES_PATH = APP_ROOT + "/static/profiles"
posted_files_image_path = APP_ROOT + "/static/posted_files/images"
posted_files_video_path = APP_ROOT + "/static/posted_files/video"

app.secret_key = "university"  # consider using env var for production
admin_name = "admin"
admin_password_plain = "admin"  # default initial admin password

# ---------- Migration / index helper (ensure version field) ----------
def ensure_version_field(collection):
    collection.update_many({"version": {"$exists": False}}, {"$set": {"version": 1}})

# create useful indexes (safe to call repeatedly)
try:
    post_collection.create_index([("room_id", pymongo.ASCENDING)])
    room_collection.create_index([("room_owner_id", pymongo.ASCENDING)])
except Exception:
    # if index creation fails, continue — not fatal for dev
    pass

# ensure existing docs have a version field so optimistic locking works
ensure_version_field(post_collection)
ensure_version_field(room_collection)

# ---------- Routes and logic (existing + added CRUD) ----------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin")
def admin():
    return render_template("admin_login.html")


# ensure an admin user exists (stores plain + hashed password as original code did)
query = {}
count = admin_collection.count_documents(query)
if count == 0:
    hashed_password = bcrypt.hashpw(admin_password_plain.encode("utf-8"), bcrypt.gensalt())
    admin_doc = {
        "username": admin_name,
        "password": admin_password_plain,
        "encrypt_password": hashed_password.decode("utf-8"),
    }
    admin_collection.insert_one(admin_doc)


@app.route("/admin_login_action", methods=["POST"])
def admin_login_action():
    name = request.form.get("name")
    pwd = request.form.get("password")
    # fix: compare to stored admin_name and admin_password_plain
    if name == admin_name and pwd == admin_password_plain:
        session["role"] = "admin"
        return redirect("/admin_home")
    else:
        return render_template("message.html", message="Invalid Admin Details")


@app.route("/room_owner")
def room_owner():
    return render_template("room_owner_login.html")


@app.route("/room_owner_registration")
def room_owner_registration():
    return render_template("room_owner_registration.html")


@app.route("/room_owner_registration_action", methods=["POST"])
def room_owner_registration_action():
    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")
    email = request.form.get("email")
    phone = request.form.get("phone")
    password = request.form.get("password")
    address = request.form.get("address")
    city = request.form.get("city")
    state = request.form.get("state")
    zip_code = request.form.get("zip_code")

    query = {"email": email}
    count = room_owner_collection.count_documents(query)
    if count > 0:
        return render_template("message.html", message="Email Already Exists")
    query = {"phone": phone}
    count = room_owner_collection.count_documents(query)
    if count > 0:
        return render_template("message.html", message="Phone Number Already Exists")

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    doc = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "phone": phone,
        "password": password,
        "encrypt_password": hashed_password.decode("utf-8"),
        "address": address,
        "city": city,
        "state": state,
        "zip_code": zip_code,
        "isLogged": False,
        "version": 1,
    }
    room_owner_collection.insert_one(doc)
    return render_template("admin_message.html", message="Room Owner Added successfully")


@app.route("/room_owner_login_action", methods=["POST"])
def room_owner_login_action():
    email = request.form.get("email")
    password = request.form.get("password")
    query = {"email": email, "password": password}
    count = room_owner_collection.count_documents(query)
    if count > 0:
        room_owner = room_owner_collection.find_one(query)
        # if isLogged True then redirect home, else force password change (as original)
        if room_owner.get("isLogged"):
            session["room_owner_id"] = str(room_owner["_id"])
            session["role"] = "room_owner"
            return redirect("/room_owner_home")
        else:
            session["role"] = "room_owner"
            session["room_owner_id"] = str(room_owner["_id"])
            return render_template("change_room_owner_password.html")
    else:
        return render_template("message.html", message="Invalid Room Owner Details")


@app.route("/change_room_owner_password_action", methods=["POST"])
def change_room_owner_password_action():
    old_password = request.form.get("old_password")
    password = request.form.get("password")
    room_owner = room_owner_collection.find_one({"_id": ObjectId(session.get("room_owner_id"))})
    if not room_owner:
        return render_template("message.html", message="Invalid session or room owner")
    if room_owner.get("password") != old_password:
        return render_template("message.html", message="Invalid Old Password...!")
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    query = {"$set": {"password": password, "encrypt_password": hashed_password.decode("utf-8"), "isLogged": True}}
    room_owner_collection.update_one({"_id": ObjectId(session.get("room_owner_id"))}, query)
    session["room_owner_id"] = str(room_owner["_id"])
    session["role"] = "room_owner"
    return redirect("/room_owner_home")


@app.route("/member")
def member():
    return render_template("member_login.html")


@app.route("/member_registration")
def member_registration():
    return render_template("member_registration.html")


@app.route("/member_registration_action", methods=["POST"])
def member_registration_action():
    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")
    email = request.form.get("email")
    phone = request.form.get("phone")
    password = request.form.get("password")
    address = request.form.get("address")
    city = request.form.get("city")
    state = request.form.get("state")
    zip_code = request.form.get("zip_code")
    query = {"email": email}
    count = member_collection.count_documents(query)
    if count > 0:
        return render_template("message.html", message="Email Already Exists")
    query = {"phone": phone}
    count = member_collection.count_documents(query)
    if count > 0:
        return render_template("message.html", message="Phone Number Already Exists")
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    doc = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "phone": phone,
        "password": password,
        "encrypt_password": hashed_password.decode("utf-8"),
        "address": address,
        "city": city,
        "state": state,
        "zip_code": zip_code,
        "version": 1,
    }
    member_collection.insert_one(doc)
    return render_template("message.html", message="Member Registered successfully")


@app.route("/member_login_action", methods=["POST"])
def member_login_action():
    email = request.form.get("email")
    password = request.form.get("password")
    query = {"email": email, "password": password}
    count = member_collection.count_documents(query)
    if count > 0:
        member = member_collection.find_one(query)
        session["role"] = "member"
        session["member_id"] = str(member["_id"])
        return redirect("/member_home")
    else:
        return render_template("message.html", message="Invalid Email and Password")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/admin_home")
def admin_home():
    return render_template("admin_home.html")


@app.route("/room_categories")
def room_categories():
    message = request.args.get("message")
    if message is None:
        message = ""
    room_categories = room_categories_collection.find({})
    room_categories = list(room_categories)
    return render_template("room_categories.html", room_categories=room_categories, message=message)


@app.route("/room_categories_action")
def room_categories_action():
    category_name = request.args.get("category_name")
    query = {"category_name": category_name}
    count = room_categories_collection.count_documents(query)
    if count > 0:
        return redirect("room_categories?message=Already added this category")
    else:
        room_categories_collection.insert_one(query)
        return redirect("room_categories?message=Room category added Successfully")


@app.route("/view_room_owners")
def view_room_owners():
    query = {}
    keyword = request.args.get("keyword")
    if session.get("role") == "admin":
        if keyword is None:
            keyword = ""
        if keyword == "":
            query = {}
        else:
            keyword2 = re.compile(".*" + str(keyword) + ".*", re.IGNORECASE)
            query = {"$or": [{"first_name": keyword2}, {"email": keyword2}, {"last_name": keyword2}, {"phone": keyword}]}
    room_owners = room_owner_collection.find(query)
    room_owners = list(room_owners)
    return render_template("view_room_owners.html", room_owners=room_owners)


@app.route("/add_room")
def add_room():
    room_categories = room_categories_collection.find({})
    room_categories = list(room_categories)
    room_owners = room_owner_collection.find({})
    room_owners = list(room_owners)
    return render_template("add_room.html", room_categories=room_categories, room_owners=room_owners)


@app.route("/add_room_action", methods=["POST"])
def add_room_action():
    room_title = request.form.get("room_title")
    category_id = request.form.get("category_id")
    room_owner_id = request.form.get("room_owner_id")
    description = request.form.get("description")
    created_on = datetime.datetime.now()
    created_by = "Admin"
    status = "Room Created"
    doc = {
        "room_title": room_title,
        "category_id": ObjectId(category_id),
        "room_owner_id": ObjectId(room_owner_id),
        "description": description,
        "created_on": created_on,
        "created_by": created_by,
        "status": status,
        "version": 1,
    }
    room_collection.insert_one(doc)
    return render_template("admin_message.html", message="Room Created Successfully")


@app.route("/view_room")
def view_room():
    query = {}
    rooms = room_collection.find(query)
    rooms = list(rooms)
    return render_template(
        "view_room.html",
        rooms=rooms,
        get_room_owner_id_by_room=get_room_owner_id_by_room,
        get_room_category_id_by_room=get_room_category_id_by_room,
        get_room_member_id_by_room_member=get_room_member_id_by_room_member,
        get_is_in_room_by_room_id=get_is_in_room_by_room_id,
        get_is_in_room_by_room_id2=get_is_in_room_by_room_id2,
    )


def get_room_owner_id_by_room(room_owner_id):
    query = {"_id": ObjectId(room_owner_id)}
    room_owner = room_owner_collection.find_one(query)
    return room_owner


def get_room_category_id_by_room(category_id):
    query = {"_id": ObjectId(category_id)}
    room_category = room_categories_collection.find_one(query)
    return room_category


def get_room_member_id_by_room_member(member_id):
    query = {"_id": ObjectId(member_id)}
    member = member_collection.find_one(query)
    return member


@app.route("/member_home")
def member_home():
    return render_template("member_home.html")


@app.route("/room_owner_home")
def room_owner_home():
    return render_template("room_owner_home.html")


@app.route("/send_room_join_request")
def send_room_join_request():
    member_id = session.get("member_id")
    room_id = request.args.get("room_id")
    if not member_id or not room_id:
        return redirect("/view_room")
    status = "Join Requested"
    joining_date = datetime.datetime.now()
    room_member = {"member_id": ObjectId(member_id), "status": status, "joining_date": joining_date}
    query = {"$push": {"room_members": room_member}}
    room_collection.update_one({"_id": ObjectId(room_id)}, query)
    return redirect("/view_room")


@app.route("/accept_room_request")
def accept_room_request():
    room_id = request.args.get("room_id")
    member_id = request.args.get("member_id")
    query1 = {"_id": ObjectId(room_id), "room_members.member_id": ObjectId(member_id)}
    query2 = {"$set": {"room_members.$.status": "Accepted"}}
    room_collection.update_one(query1, query2)
    return redirect("/view_rooms_by_room_owner")


@app.route("/reject_room_request")
def reject_room_request():
    room_id = request.args.get("room_id")
    member_id = request.args.get("member_id")
    query1 = {"_id": ObjectId(room_id), "room_members.member_id": ObjectId(member_id)}
    query2 = {"$set": {"room_members.$.status": "Rejected"}}
    room_collection.update_one(query1, query2)
    return redirect("/view_rooms_by_room_owner")


@app.route("/block_member")
def block_member():
    room_id = request.args.get("room_id")
    member_id = request.args.get("member_id")
    query1 = {"_id": ObjectId(room_id), "room_members.member_id": ObjectId(member_id)}
    query2 = {"$set": {"room_members.$.status": "Blocked"}}
    room_collection.update_one(query1, query2)
    return redirect("/view_rooms_by_room_owner")


@app.route("/un_block_member")
def un_block_member():
    room_id = request.args.get("room_id")
    member_id = request.args.get("member_id")
    query1 = {"_id": ObjectId(room_id), "room_members.member_id": ObjectId(member_id)}
    query2 = {"$set": {"room_members.$.status": "Accepted"}}
    room_collection.update_one(query1, query2)
    return redirect("/view_rooms_by_room_owner")


@app.route("/view_rooms_by_room_owner")
def view_rooms_by_room_owner():
    query = {}
    if session.get("role") == "room_owner":
        room_owner_id = session.get("room_owner_id")
        # If you want to restrict view to owner, uncomment filter below:
        # query = {"room_owner_id": ObjectId(room_owner_id)}
        query = {}
    elif session.get("role") == "admin":
        query = {}
    rooms = room_collection.find(query)
    rooms = list(rooms)
    return render_template(
        "view_rooms_by_room_owner.html",
        rooms=rooms,
        get_room_owner_id_by_room=get_room_owner_id_by_room,
        get_room_category_id_by_room=get_room_category_id_by_room,
        get_room_member_id_by_room_member=get_room_member_id_by_room_member,
        str=str,
    )


@app.route("/view_requests")
def view_requests():
    room_id = request.args.get("room_id")
    query = {"_id": ObjectId(room_id)}
    rooms = room_collection.find_one(query)
    return render_template("view_requests.html", room=rooms, get_room_member_id_by_room_member=get_room_member_id_by_room_member)


@app.route("/goto_my_room")
def goto_my_room():
    room_id = request.args.get("room_id")
    if not room_id:
        return redirect("/view_room")
    query = {"room_id": ObjectId(room_id)}
    posts = post_collection.find(query)
    posts = list(posts)
    return render_template(
        "goto_my_room.html",
        room_id=room_id,
        posts=posts,
        get_like_count=get_like_count,
        get_comment_count=get_comment_count,
        get_posted_by_post=get_posted_by_post,
        get_member_by_post=get_member_by_post,
        get_room_by_room_id=get_room_by_room_id,
    )


def get_like_count(post_id):
    post = post_collection.find_one({"_id": ObjectId(post_id)})
    if not post:
        return 0
    if "likes" in post:
        return len(post["likes"])
    return 0


def get_comment_count(post_id):
    post = post_collection.find_one({"_id": ObjectId(post_id)})
    if not post:
        return 0
    if "comments" in post:
        return len(post["comments"])
    return 0


def get_posted_by_post(room_owner_id):
    room_owner = room_owner_collection.find_one({"_id": ObjectId(room_owner_id)})
    return room_owner


def get_member_by_post(member_id):
    member = member_collection.find_one({"_id": ObjectId(member_id)})
    return member


@app.route("/add_post")
def add_post():
    room_id = request.args.get("room_id")
    return render_template("add_post.html", room_id=room_id)


@app.route("/add_post_action", methods=["POST"])
def add_post_action():
    room_id = request.form.get("room_id")
    title = request.form.get("title")
    image = request.files.get("image")
    video = request.files.get("video")
    description = request.form.get("description")
    image_filename = ""
    video_filename = ""
    if image and image.filename:
        image_filename = image.filename
        path = posted_files_image_path + "/" + image_filename
        os.makedirs(os.path.dirname(path), exist_ok=True)
        image.save(path)
    if video and video.filename:
        video_filename = video.filename
        path2 = posted_files_video_path + "/" + video_filename
        os.makedirs(os.path.dirname(path2), exist_ok=True)
        video.save(path2)

    now = datetime.datetime.now()
    if session.get("role") == "room_owner":
        room_owner_id = session.get("room_owner_id")
        doc = {
            "title": title,
            "image": image_filename,
            "video": video_filename,
            "description": description,
            "room_id": ObjectId(room_id),
            "room_owner_id": ObjectId(room_owner_id),
            "status": "Posted",
            "created_at": now,
            "updated_at": now,
            "version": 1,
        }
    else:
        member_id = session.get("member_id")
        doc = {
            "title": title,
            "image": image_filename,
            "video": video_filename,
            "description": description,
            "room_id": ObjectId(room_id),
            "member_id": ObjectId(member_id),
            "status": "Posted",
            "created_at": now,
            "updated_at": now,
            "version": 1,
        }
    post_collection.insert_one(doc)
    return redirect("/goto_my_room?room_id=" + room_id)


@app.route("/get_comments")
def get_comments():
    post_id = request.args.get("post_id")
    query = {"_id": ObjectId(post_id)}
    post = post_collection.find_one(query)
    return render_template("get_comments.html", post_id=post_id, post=post, get_room_owner_id_by_comments=get_room_owner_id_by_comments, get_member_id_by_comments=get_member_id_by_comments)


@app.route("/get_comment_action")
def get_comment_action():
    post_id = request.args.get("post_id")
    comment = request.args.get("comment")
    commented_on = datetime.datetime.now()
    if session.get("role") == "room_owner":
        room_owner_id = session.get("room_owner_id")
        comments = {"commented_on": commented_on, "comment": comment, "room_owner_id": ObjectId(room_owner_id)}
        query = {"$push": {"comments": comments}, "$inc": {"version": 1}}
    elif session.get("role") == "member":
        member_id = session.get("member_id")
        comments = {"commented_on": commented_on, "comment": comment, "member_id": ObjectId(member_id)}
        query = {"$push": {"comments": comments}, "$inc": {"version": 1}}
    else:
        return redirect("/get_comments?post_id=" + post_id)
    post_collection.update_one({"_id": ObjectId(post_id)}, query)
    return redirect("/get_comments?post_id=" + post_id)


def get_room_owner_id_by_comments(room_owner_id):
    query = {"_id": ObjectId(room_owner_id)}
    room_owner = room_owner_collection.find_one(query)
    return room_owner


def get_member_id_by_comments(member_id):
    query = {"_id": ObjectId(member_id)}
    member = member_collection.find_one(query)
    return member


# ---------- Safer atomic like (replaces previous add_like) ----------
@app.route("/add_like")
def add_like():
    post_id = request.args.get("post_id")
    if not post_id:
        return {"error": "post_id required"}, 400

    if session.get("role") == "member":
        member_id = ObjectId(session.get("member_id"))
        res = post_collection.update_one(
            {"_id": ObjectId(post_id), "likes.member_id": {"$ne": member_id}},
            {"$push": {"likes": {"member_id": member_id, "liked_on": datetime.datetime.now()}}, "$inc": {"version": 1}},
        )
        return {"matched": res.matched_count, "modified": res.modified_count}
    elif session.get("role") == "room_owner":
        room_owner_id = ObjectId(session.get("room_owner_id"))
        res = post_collection.update_one(
            {"_id": ObjectId(post_id), "likes.room_owner_id": {"$ne": room_owner_id}},
            {"$push": {"likes": {"room_owner_id": room_owner_id, "liked_on": datetime.datetime.now()}}, "$inc": {"version": 1}},
        )
        return {"matched": res.matched_count, "modified": res.modified_count}
    return {"error": "invalid role or not logged in"}, 400


@app.route("/poll")
def poll():
    room_id = request.args.get("room_id")
    query = {"room_id": ObjectId(room_id)}
    polls = polls_collection.find(query)
    return render_template(
        "poll.html",
        get_is_answer_poll_id=get_is_answer_poll_id,
        get_poll_count_by_poll_id2=get_poll_count_by_poll_id2,
        room_id=room_id,
        polls=polls,
        get_poll_count_by_poll_id=get_poll_count_by_poll_id,
        get_submitted_count_by_poll_id=get_submitted_count_by_poll_id,
    )


@app.route("/add_poll")
def add_poll():
    room_id = request.args.get("room_id")
    return render_template("add_poll.html", room_id=room_id)


@app.route("/add_poll_action")
def add_poll_action():
    question = request.args.get("question")
    room_id = request.args.get("room_id")
    if session.get("role") == "room_owner":
        room_owner_id = session.get("room_owner_id")
        doc = {"question": question, "room_id": ObjectId(room_id), "room_owner_id": ObjectId(room_owner_id), "version": 1}
    elif session.get("role") == "member":
        member_id = session.get("member_id")
        doc = {"question": question, "room_id": ObjectId(room_id), "member_id": ObjectId(member_id), "version": 1}
    else:
        return redirect("/poll?room_id=" + room_id)
    polls_collection.insert_one(doc)
    return redirect("/poll?room_id=" + room_id)


@app.route("/room_owner_poll_submit_action")
def room_owner_poll_submit_action():
    poll_id = request.args.get("poll_id")
    room_id = request.args.get("room_id")
    poll = request.args.get("poll")
    if session.get("role") == "room_owner":
        room_owner_id = session.get("room_owner_id")
        answers = {"room_owner_id": ObjectId(room_owner_id), "poll": poll}
        query = {"$push": {"answers": answers}, "$inc": {"version": 1}}
        polls_collection.update_one({"_id": ObjectId(poll_id)}, query)
        return redirect("/poll?room_id=" + room_id)
    elif session.get("role") == "member":
        member_id = session.get("member_id")
        answers = {"member_id": ObjectId(member_id), "poll": poll}
        query = {"$push": {"answers": answers}, "$inc": {"version": 1}}
        polls_collection.update_one({"_id": ObjectId(poll_id)}, query)
        return redirect("/poll?room_id=" + room_id)
    return redirect("/poll?room_id=" + room_id)


def get_poll_count_by_poll_id(poll_id):
    poll = polls_collection.find_one({"_id": ObjectId(poll_id)})
    if not poll or "answers" not in poll:
        return 0
    count = 0
    for answer in poll["answers"]:
        if answer.get("poll") == "yes":
            count += 1
    return count


def get_poll_count_by_poll_id2(poll_id):
    poll = polls_collection.find_one({"_id": ObjectId(poll_id)})
    if not poll or "answers" not in poll:
        return 0
    count = 0
    for answer in poll["answers"]:
        if answer.get("poll") == "no":
            count += 1
    return count


def get_is_answer_poll_id(poll_id):
    # safe check: ensure member_id in session
    member_id = session.get("member_id")
    if not member_id:
        return False
    count = polls_collection.count_documents({"_id": ObjectId(poll_id), "answers.member_id": ObjectId(member_id)})
    return count != 0


def get_submitted_count_by_poll_id(poll_id):
    poll = polls_collection.find_one({"_id": ObjectId(poll_id)})
    if not poll or "answers" not in poll:
        return 0
    return len(poll["answers"])


def get_is_in_room_by_room_id(room_id):
    member_id = session.get("member_id")
    if not member_id:
        return False
    query = {"_id": ObjectId(room_id), "room_members.member_id": ObjectId(member_id), "room_members.status": {"$ne": "Rejected"}}
    count = room_collection.count_documents(query)
    return count != 0


def get_is_in_room_by_room_id2(room_id):
    member_id = session.get("member_id")
    if not member_id:
        return False
    query = {"_id": ObjectId(room_id), "room_members.member_id": ObjectId(member_id), "room_members.status": "Accepted"}
    count = room_collection.count_documents(query)
    return count != 0


def get_is_room_request_status_accepted_by_room_id(room_id):
    member_id = session.get("member_id")
    if not member_id:
        return False
    count = room_collection.count_documents({"_id": ObjectId(room_id), "room_members.member_id": ObjectId(member_id), "status": "Accepted"})
    return count != 0


@app.route("/block_post")
def block_post():
    room_id = request.args.get("room_id")
    post_id = request.args.get("post_id")
    status = "Blocked"
    query1 = {"_id": ObjectId(post_id)}
    query2 = {"$set": {"status": status}, "$inc": {"version": 1}}
    post_collection.update_one(query1, query2)
    return redirect("/goto_my_room?room_id=" + (room_id or ""))


@app.route("/edit_category")
def edit_category():
    category_id = request.args.get("category_id")
    query = {"_id": ObjectId(category_id)}
    category = room_categories_collection.find_one(query)
    return render_template("edit_category.html", category=category, category_id=category_id)


@app.route("/edit_category_action")
def edit_category_action():
    category_id = request.args.get("category_id")
    category_name = request.args.get("category_name")
    query1 = {"_id": ObjectId(category_id)}
    query2 = {"$set": {"category_name": category_name}}
    room_categories_collection.update_one(query1, query2)
    return redirect("/room_categories")


def get_room_by_room_id(room_id):
    query = {"_id": ObjectId(room_id)}
    room = room_collection.find_one(query)
    return room


@app.route("/back_to_room")
def back_to_room():
    room_id = request.args.get("room_id")
    return redirect("/goto_my_room?room_id=" + (room_id or ""))


# -----------------------
# POST CRUD (API-style) with optimistic concurrency control
# -----------------------
@app.route("/posts/<post_id>", methods=["GET"])
def api_get_post(post_id):
    try:
        post = post_collection.find_one({"_id": ObjectId(post_id)})
    except Exception:
        return {"error": "invalid id"}, 400
    if not post:
        return {"error": "not found"}, 404
    post["_id"] = str(post["_id"])
    for k in ("room_id", "member_id", "room_owner_id"):
        if k in post and post[k] is not None:
            post[k] = str(post[k])
    return post, 200


@app.route("/posts/<post_id>", methods=["PUT"])
def api_update_post(post_id):
    data = request.get_json(force=True, silent=True)
    if not data:
        return {"error": "json body required"}, 400
    client_version = data.get("version")
    if client_version is None:
        return {"error": "version required for concurrency control"}, 400

    update_fields = {}
    for f in ("title", "description", "image", "video", "status"):
        if f in data:
            update_fields[f] = data[f]

    if not update_fields:
        return {"error": "nothing to update"}, 400

    filter_doc = {"_id": ObjectId(post_id), "version": client_version}
    update_doc = {"$set": {**update_fields, "updated_at": datetime.datetime.now()}, "$inc": {"version": 1}}

    updated = post_collection.find_one_and_update(filter_doc, update_doc, return_document=ReturnDocument.AFTER)
    if updated:
        updated["_id"] = str(updated["_id"])
        for k in ("room_id", "member_id", "room_owner_id"):
            if k in updated and updated[k] is not None:
                updated[k] = str(updated[k])
        return updated, 200

    current = post_collection.find_one({"_id": ObjectId(post_id)})
    if not current:
        return {"error": "not found"}, 404
    return {"error": "conflict", "message": "document was modified by someone else", "current_version": current.get("version")}, 409


@app.route("/posts/<post_id>", methods=["DELETE"])
def api_delete_post(post_id):
    version = request.args.get("version", type=int)
    if version is None:
        return {"error": "version query parameter required"}, 400

    res = post_collection.delete_one({"_id": ObjectId(post_id), "version": version})
    if res.deleted_count == 1:
        return {"status": "deleted"}, 200
    current = post_collection.find_one({"_id": ObjectId(post_id)})
    if not current:
        return {"error": "not found"}, 404
    return {"error": "conflict", "current_version": current.get("version")}, 409


# -----------------------
# ROOM CRUD (optimistic locking)
# -----------------------
@app.route("/rooms/<room_id>", methods=["GET"])
def api_get_room(room_id):
    try:
        room = room_collection.find_one({"_id": ObjectId(room_id)})
    except Exception:
        return {"error": "invalid id"}, 400
    if not room:
        return {"error": "not found"}, 404
    room["_id"] = str(room["_id"])
    if "room_owner_id" in room and room["room_owner_id"]:
        room["room_owner_id"] = str(room["room_owner_id"])
    if "category_id" in room and room["category_id"]:
        room["category_id"] = str(room["category_id"])
    return room, 200


@app.route("/rooms/<room_id>", methods=["PUT"])
def api_update_room(room_id):
    data = request.get_json(force=True, silent=True)
    if not data:
        return {"error": "json required"}, 400
    client_version = data.get("version")
    if client_version is None:
        return {"error": "version required"}, 400

    update_fields = {}
    for f in ("room_title", "description", "status", "category_id", "room_owner_id"):
        if f in data:
            if f in ("category_id", "room_owner_id") and data[f]:
                try:
                    update_fields[f] = ObjectId(data[f])
                except Exception:
                    return {"error": f"invalid {f}"}, 400
            else:
                update_fields[f] = data[f]

    if not update_fields:
        return {"error": "nothing to update"}, 400

    filter_doc = {"_id": ObjectId(room_id), "version": client_version}
    update_doc = {"$set": {**update_fields, "updated_at": datetime.datetime.now()}, "$inc": {"version": 1}}
    updated = room_collection.find_one_and_update(filter_doc, update_doc, return_document=ReturnDocument.AFTER)
    if updated:
        updated["_id"] = str(updated["_id"])
        return updated, 200

    current = room_collection.find_one({"_id": ObjectId(room_id)})
    if not current:
        return {"error": "not found"}, 404
    return {"error": "conflict", "current_version": current.get("version")}, 409


@app.route("/rooms/<room_id>", methods=["DELETE"])
def api_delete_room(room_id):
    version = request.args.get("version", type=int)
    if version is None:
        return {"error": "version required"}, 400
    res = room_collection.delete_one({"_id": ObjectId(room_id), "version": version})
    if res.deleted_count == 1:
        return {"status": "deleted"}, 200
    current = room_collection.find_one({"_id": ObjectId(room_id)})
    if not current:
        return {"error": "not found"}, 404
    return {"error": "conflict", "current_version": current.get("version")}, 409


# ---------- End of new CRUD & concurrency code ----------

if __name__ == "__main__":
    app.run(debug=True)
