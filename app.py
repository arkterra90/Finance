# Doesn't check for duplicate user names in register


import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    symbol_index = db.execute("SELECT DISTINCT symbol FROM user_index WHERE user_id=?;", session["user_id"])
    symbol_shares = {}

    for i in range(len(symbol_index)):
        current_symbol = symbol_index[i]["symbol"]
        x = db.execute("SELECT SUM(shares_owned) FROM user_index WHERE user_id=? AND symbol=?;", session["user_id"], current_symbol)
        symbol_shares[current_symbol] = x[0]["SUM(shares_owned)"]
    symbol_prices = {}

    for i in range(len(symbol_index)):
        current_symbol = symbol_index[i]["symbol"]
        price = lookup(current_symbol)
        symbol_prices[current_symbol] = price["price"]

    total_value = {}
    for i in range(len(symbol_index)):
        current_symbol = symbol_index[i]["symbol"]
        x2 = db.execute("SELECT SUM(shares_owned) FROM user_index WHERE user_id=? AND symbol=?;", session["user_id"], current_symbol)
        price = lookup(current_symbol)
        total_value[current_symbol] = price["price"] * x2[0]["SUM(shares_owned)"]

    cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])
    cash_bal = cash[0]["cash"]
    holding_value = 0

    for symbol in total_value:
        holding_value += total_value[symbol]

    user_sum = cash_bal + holding_value
    user_fin = [cash_bal, holding_value, user_sum]

    return render_template("index.html", symbol_shares=symbol_shares, symbol_prices=symbol_prices, total_value=total_value, user_fin=user_fin)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Allows user to buy shares of stock"""

    # If method is Post retrieves stock symbol and desired amount of shares
    # Returns apology is either field is blank
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Check for valid input
        stock = lookup(symbol)
        if stock == None:
            return apology("Invalid Stock Symbol", 400)

        try:
            shares = int(request.form.get("shares"))

        except ValueError:
            return apology("Enter valid amount of shares", 400)

        if shares <= 0:
            return apology("Enter valid amount of shares", 400)

        # Gets stock price from API call, session user id, and available cash for user

        stock_price = stock["price"]
        userid = int(session.get("user_id"))
        cash = db.execute("SELECT cash FROM users WHERE id = ?;", userid)

        # Checks if user has enough cash for purchase
        price = float(shares) * stock_price
        if cash[0]["cash"] < price:
            return apology("Insufficent funds")

        # Stores purchases in finance.db
        db.execute("INSERT INTO buy (user_id, symbol, price, quantity) VALUES (?, ?, ?, ?);", session["user_id"], symbol, price, shares)
        db.execute("UPDATE users SET cash=? WHERE id=?;", cash[0]["cash"] - price, session["user_id"])
        db.execute("INSERT INTO user_index (symbol, shares_owned, user_id) VALUES (?, ?, ?);", symbol, shares, session["user_id"])

        return redirect("/")

    # If method get returns buy.html
    else:
        return render_template("buy.html")




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    purchases = db.execute("SELECT symbol, quantity FROM buy WHERE user_id=?;", session["user_id"])
    sold = db.execute("SELECT symbol, shares_sold FROM user_sold WHERE user_id=?;", session["user_id"])

    return render_template("history.html", purchases=purchases, sold=sold)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Stock Quote"""

    # If user enters a stock ticker and submits for quote loads quoted.html page to display info
    if request.method == "POST":

        symbol = request.form.get("symbol")
        stock_quote = lookup(symbol)
        if stock_quote == None:
            return apology("Invalid Ticker", 400)

        return render_template("quoted.html", stock_quote=stock_quote)

    # Initial quote page for user input
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """ User Registration Page """

    # If new user correctly registers username and password a new username and the hash of their password is
    # stored in the relational database.

    if request.method == "POST":
        # Inputs from new user
        new_user = request.form.get("username")
        pass1 = request.form.get("password")
        pass2 = request.form.get("confirmation")

        # Checks for password match and generates hash of password
        if (pass1 != pass2):
            return apology("Passwords Don't Match", 400)
        new_pass = generate_password_hash(request.form.get("password"))
        unique_user_name = db.execute("SELECT * FROM users WHERE username =?", new_user)

        # Checks for input from new user in fields stores in DB if input detected
        if len(unique_user_name) > 0:
            return apology("user name exist", 400)
        if (len(new_user) == 0):
            return apology("Please input user name", 400)
        if (len(pass1) == 0):
            return apology("Please input a matchinig password", 400)
        users = db.execute("SELECT username FROM users;")
        if new_user in users:
            return apology("user name taken", 400)
        db.execute("INSERT INTO users (username, hash) VALUES (?,?);", new_user, new_pass)

        return redirect("/")

    # Initial render of register.html for new user registration.
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        # Gets user input and calls info for symbol requested to sell
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        symbol_info = lookup(symbol)

        # Checks for valid inputs
        if symbol_info == None:
            return apology("Invalid Stock Symbol", 400)

        try:
            shares = int(request.form.get("shares"))

        except ValueError:
            return apology("Enter valid amount of shares", 400)

        if shares <= 0:
            return apology("Enter valid amount of shares", 400)

        # Executes sell by updating SQL tables and logging sell in user_sold table
        cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])
        cash_bal = cash[0]["cash"]

        cost = symbol_info["price"] * shares

        symbol_index = db.execute("SELECT DISTINCT symbol FROM user_index WHERE user_id=?;", session["user_id"])
        symbol_shares = {}

        for i in range(len(symbol_index)):
            current_symbol = symbol_index[i]["symbol"]
            x1 = db.execute("SELECT SUM(shares_owned) FROM user_index WHERE user_id=? AND symbol=?;", session["user_id"], current_symbol)
            symbol_shares[current_symbol] = x1[0]["SUM(shares_owned)"]

        if symbol in symbol_shares:
            if symbol_shares[symbol] <= shares:
                return apology("Not Enough Shares For Transactioin", 400)

        db.execute("INSERT INTO user_sold (user_id, symbol, shares_sold) VALUES (?, ?, ?);", session["user_id"], symbol, shares)
        db.execute("UPDATE users SET cash=? WHERE id=?;", cash_bal + cost, session["user_id"])
        db.execute("INSERT INTO user_index (symbol, shares_owned, user_id) VALUES (?, ?, ?);", symbol, -shares, session["user_id"])

        return redirect("/")

    else:

        # Renders sell.html with select menu listing shares owned by user
        symbol_index = db.execute("SELECT DISTINCT symbol FROM user_index WHERE user_id=?;", session["user_id"])
        for i in range(len(symbol_index)):
            symbol_name = symbol_index[i]["symbol"]

        return render_template("sell.html", symbol_shares=symbol_name)

@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    if request.method == "POST":

        updated_password = request.form.get("updated_password")
        confirmation = request.form.get("confirmation")

        if updated_password != confirmation:
            return apology("Passwords do not match", 400)

        if len(updated_password) == 0:
            return apology("Please enter a new password", 400)

        pass_hash = generate_password_hash(updated_password)

        db.execute("UPDATE users SET hash=? WHERE id=?;", pass_hash, session["user_id"])
        return redirect("/")

    else:
        return render_template("edit.html")