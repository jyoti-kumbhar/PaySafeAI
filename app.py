from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import joblib
import pandas as pd
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import certifi
from predict import predict_transaction  

# -----------------------------
# Flask setup
# -----------------------------
app = Flask(__name__)
app.secret_key = "yoursecretkey"  # Needed for sessions

# -----------------------------
# MongoDB Atlas connection
# -----------------------------
MONGO_URI = "mongodb+srv://kumbharjyotics232444:2rJuzrAMbUS9ZtQB@cluster0.rlkth.mongodb.net/PaySafeAI?retryWrites=true&w=majority"
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client["PaySafeAI"]
users_col = db["users"]
history_col = db["history"]

# -----------------------------
# Load ML model
# -----------------------------
model = joblib.load("fraud_model.pkl")

# -----------------------------
# Page Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login.html")
def login_page():
    return render_template("login.html")

@app.route("/signup.html")
def signup_page():
    return render_template("signup.html")

@app.route("/index_user.html")
def index_user():
    if "user" not in session:
        return redirect(url_for("login_page"))
    return render_template("index_user.html")

@app.route("/index_admin.html")
def index_admin():
    if "user" not in session:
        return redirect(url_for("login_page"))
    # only allow if role is admin
    if session.get("role") != "admin":
        return redirect(url_for("index_user"))
    return render_template("index_admin.html")

@app.route("/user_profile.html")
def user_profile():
    if "user" not in session:
        return redirect(url_for("login_page"))
    return render_template("user_profile.html")

@app.route("/user_history.html")
def user_history():
    if "user" not in session:
        return redirect(url_for("login_page"))
    return render_template("user_history.html")

@app.route("/user_transaction_form.html")
def user_transaction_form():
    if "user" not in session:
        return redirect(url_for("login_page"))
    return render_template("user_transaction_form.html")

@app.route("/admin_user.html")
def admin_user():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login_page"))
    return render_template("admin_user.html")

@app.route("/admin_dashboard.html")
def admin_dashboard():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login_page"))
    return render_template("admin_dashboard.html")

# -----------------------------
# API Routes
# -----------------------------
@app.route("/api/predict", methods=["POST"])
def api_predict():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    try:
        result = predict_transaction(data)
    except Exception as e:
        print("Prediction error:", e)
        return jsonify({"error": "Prediction failed"}), 500

    # Save to history
    history_col.insert_one({"username": session["user"], **data, "prediction": result})

    return jsonify({"prediction": result})

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if users_col.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = generate_password_hash(password)
    # ✅ Always store role as "user"
    users_col.insert_one({
        "name": name,
        "email": email,
        "password": hashed_pw,
        "role": "user"
    })
    return jsonify({"message": "Signup successful"}), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = users_col.find_one({"email": email})
    if user and check_password_hash(user["password"], password):
        session["user"] = email
        session["role"] = user.get("role", "user")  # ✅ default fallback

        return jsonify({
            "message": "Login successful",
            "user": {"email": user["email"], "role": session["role"]}
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/user/<email>", methods=["GET", "PUT"])
def user_profile_api(email):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = users_col.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == "GET":
        return jsonify({"name": user.get("name"), "email": user.get("email"), "role": user.get("role", "user")})

    if request.method == "PUT":
        data = request.json
        update_data = {
            "name": data.get("name", user.get("name")),
            "email": data.get("email", user.get("email"))
        }
        if data.get("password"):
            update_data["password"] = generate_password_hash(data.get("password"))

        users_col.update_one({"email": email}, {"$set": update_data})
        session["user"] = update_data["email"]
        return jsonify({"user": update_data})

@app.route("/api/predict", methods=["POST"])
def predict():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    df = pd.DataFrame([request.json])
    result = model.predict(df)[0]

    history_col.insert_one({"username": session["user"], **request.json, "prediction": str(result)})
    return jsonify({"prediction": str(result)})

@app.route("/api/history", methods=["GET"])
def history():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    records = list(history_col.find({"username": session["user"]}, {"_id": 0}))
    return jsonify(records)

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    session.pop("role", None)
    return jsonify({"message": "Logged out successfully"})

# -----------------------------
# Admin APIs
# -----------------------------
@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    if "user" not in session or session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401

    users = list(users_col.find({}, {"_id": {"$toString": "$_id"}, "name": 1, "email": 1, "role": 1}))
    return jsonify(users)


@app.route("/api/admin/users/<id>", methods=["DELETE"])
def delete_user(id):
    if "user" not in session or session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401

    from bson import ObjectId
    users_col.delete_one({"_id": ObjectId(id)})
    return jsonify({"message": "User deleted"})


@app.route("/api/admin/dashboard", methods=["GET"])
def admin_dashboard_api():
    if "user" not in session or session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401

    total_tx = history_col.count_documents({})
    fraud_tx = history_col.count_documents({"prediction": "1"})   # assuming fraud = "1"
    safe_tx = history_col.count_documents({"prediction": "0"})    # assuming safe = "0"

    return jsonify({
        "total": total_tx,
        "frauds": fraud_tx,
        "safe": safe_tx,
        "model_version": "v1.0"   # static for now
    })

# -----------------------------
# Run server
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
