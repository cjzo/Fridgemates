import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///fridge.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET"])
@login_required
def index():
    """Show portfolio of stocks"""

    names = db.execute(
        "SELECT name FROM roommates WHERE user_id = ?",
        session["user_id"],
    )

    # Gets person's space
    userinfo = db.execute(
        "SELECT space, hall, roomnum FROM users WHERE id = ?", session["user_id"]
    )

    space = userinfo[0]["space"]
    dorm = userinfo[0]["hall"] + " " + userinfo[0]["roomnum"]

    fridge = db.execute(
        "SELECT * FROM storage WHERE user_id = ? ORDER BY timestamp ASC",
        session["user_id"],
    )

    # Current date-time
    now = datetime.now()

    # Sets number of expired items
    expired = 0

    for item in fridge:
        # If the user inputs an improper time just set the time to be 0-0-0
        try:
            timestamp = datetime.strptime(item["timestamp"], "%Y-%m-%d")
        except ValueError:
            timestamp = datetime.strptime("0-0-0", "%Y-%m-%d")

        difference = timestamp - now
        item["days_left"] = difference.days + 1
        if item["days_left"] <= 0:
            expired += 1
        item["space"] = int(item["quantity"]) * int(item["size"])

    # Renders the page
    return render_template(
        "index.html",
        fridge=fridge,
        space=space,
        expired=expired,
        names=names,
        dorm=dorm,
    )


@app.route("/remove", methods=["POST"])
def remove_item():
    item_id = request.form.get("item_id")
    user_id = session["user_id"]
    current = db.execute(
        "SELECT * FROM storage WHERE user_id = ? AND id = ?", user_id, item_id
    )[0]
    roommate_list = db.execute("SELECT name FROM roommates WHERE user_id = ?", user_id)

    roommate_names = [person["name"] for person in roommate_list]

    print(roommate_names)

    roommate = request.form.get("dropdown")

    # Checks to see that a roommate is selected and is chosen
    if roommate not in roommate_names:
        flash("Roommate needs to be selected")
        return redirect("/")

    # Updates user's fridge space
    db.execute(
        "UPDATE users SET space = space + ? WHERE id = ?",
        (current["quantity"] * current["size"]),
        user_id,
    )

    # Records the removal into transactions table
    db.execute(
        "INSERT INTO transactions (user_id, name, size, quantity, roommate, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        current["user_id"],
        current["name"],
        current["size"],
        -current["quantity"],
        roommate,
        current["timestamp"],
    )

    # Removes item from storage
    db.execute("DELETE FROM storage WHERE user_id = ? AND id = ?", user_id, item_id)

    flash("Removed Item")

    return redirect("/")


@app.route("/insert", methods=["GET", "POST"])
@login_required
def insert():
    """Insert items into the fridge"""

    # Gets roommate names
    names = db.execute(
        "SELECT name FROM roommates WHERE user_id = ?",
        session["user_id"],
    )

    # Post request
    if request.method == "POST":
        # Gets form data
        user_id = session["user_id"]
        item = request.form.get("item").capitalize()
        quantity = request.form.get("quantity")
        name = request.form.get("roommate")
        date = request.form.get("expiration")

        # Edge-case catching
        if request.form.get("size") is None:
            flash("Missing Size")
            return redirect("/insert")

        if name is None:
            flash("Missing Roommate Name")
            return redirect("/insert")

        if date is None:
            flash("Missing Expiration Date")
            return redirect("/insert")

        if not item:
            flash("Missing Item")
            return redirect("/insert")

        if not quantity.isdigit():
            flash("Invalid Quantity")
            return redirect("/insert")

        if int(quantity) < 1:
            flash("Invalid Quantity")
            return redirect("/insert")

        # Dictionary to map selection to unit size
        size_to_number = {
            "extrasmall": 1,
            "small": 2,
            "medium": 4,
            "large": 8,
            "extralarge": 16,
        }

        size = size_to_number[request.form.get("size")]

        space = db.execute("SELECT space FROM users WHERE id = ?", user_id)
        if size * int(quantity) > space[0]["space"]:
            flash("Item(s) Too Large")
            return redirect("/insert")

        # Checks to see if "transactions" table exists
        try:
            db.execute("SELECT * FROM transactions LIMIT 1")
        except Exception:
            db.execute(
                "CREATE TABLE transactions (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, size INTEGER, quantity INTEGER, roommate TEXT, timestamp DATETIME)"
            )

        # Checks to see if "storage" table exists
        try:
            db.execute("SELECT * FROM storage LIMIT 1")
        except Exception:
            db.execute(
                "CREATE TABLE storage (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, size INTEGER, quantity INTEGER, roommate TEXT, timestamp DATETIME)"
            )

        # Updates storage, transaction table and user's space
        db.execute(
            "INSERT INTO transactions (user_id, name, size, quantity, roommate, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            user_id,
            item,
            size,
            int(quantity),
            name,
            date,
        )

        db.execute(
            "INSERT INTO storage (user_id, name, size, quantity, roommate, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            user_id,
            item,
            size,
            int(quantity),
            name,
            date,
        )

        db.execute(
            "UPDATE users SET space = space - ? WHERE id = ?",
            (int(quantity) * size),
            user_id,
        )

        flash("Item Added")

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("insert.html", names=names)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Gets the database of transactions
    history = db.execute(
        "SELECT * FROM transactions WHERE user_id = ?", session["user_id"]
    )

    # Renders the page
    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide username")
            return redirect("/login")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must provide password")
            return redirect("/login")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            flash("Invalid username and/or password")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/roommate", methods=["GET", "POST"])
@login_required
def roommate():
    # Gets roommate names
    names = db.execute(
        "SELECT name FROM roommates WHERE user_id = ?",
        session["user_id"],
    )

    # Post method
    if request.method == "POST":
        # Gets data about the symbol and current status
        name = request.form.get("roommate").capitalize()
        user_id = session["user_id"]
        rows = db.execute("SELECT * FROM roommates WHERE name = ?", name)

        # If the symbol doesnt exist, throw show a flash message
        if not name:
            flash("No Name")
            return redirect("/roommate")

        # If roommate doesn't already exist
        if len(rows) == 0:
            db.execute(
                "INSERT INTO roommates (user_id, name) VALUES (?, ?)", user_id, name
            )
        else:
            db.execute(
                "DELETE FROM roommates WHERE user_id = ? AND name = ?", user_id, name
            )

        # Redirect user to roommate page again
        return redirect("/roommate")

    else:
        return render_template("roommate.html", names=names)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Gets data from forms
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hall = request.form.get("hall")
        roomnum = request.form.get("number").upper()

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username was submitted
        if not username:
            flash("Must provide username")
            return redirect("/register")

        # Ensure username is unique
        elif len(rows) != 0:
            flash("Username already exists")
            return redirect("/register")

        # Ensure password was submitted
        elif not password:
            flash("Must provide password")
            return redirect("/register")

        # Ensure password was submitted
        elif not confirmation:
            flash("Must provide password (again)")
            return redirect("/register")

        # Ensure passwords match
        elif confirmation != password:
            flash("Passwords must match")
            return redirect("/register")

        elif not hall:
            flash("Must provide hall name")
            return redirect("/register")

        elif not roomnum:
            flash("Must provide room number")
            return redirect("/register")

        # Adds user into the database
        db.execute(
            "INSERT INTO users (username, hash, hall, roomnum) VALUES (?, ?, ?, ?)",
            username,
            generate_password_hash(password),
            hall,
            roomnum,
        )

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        session["user_id"] = rows[0]["id"]

        # Creates roommates table
        try:
            db.execute("SELECT * FROM roommates LIMIT 1")
        except Exception:
            db.execute("CREATE TABLE roommates (user_id INTEGER, name TEXT)")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/info", methods=["GET"])
@login_required
def info():
    return render_template("info.html")
