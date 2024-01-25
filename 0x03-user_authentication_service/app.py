#!/usr/bin/env python3
"""Flask app module
"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth
from sqlalchemy.orm.exc import NoResultFound
from user import User


AUTH = Auth()
app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    """Define the home route
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    """Handles user creation
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = AUTH.register_user(email, password)
        return jsonify(dict(email=email, message="user created"))
    except ValueError as e:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """Login a user
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    resp = jsonify({"email": email, "message": "logged in"})
    resp.set_cookie("session_id", session_id)
    return resp


@app.route("/sessions", methods=["DELETE"])
def logout():
    """Logout a user
    """
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            AUTH.destroy_session(user.id)
            return redirect("/")
    abort(403)


@app.route("/profile", methods=["GET"])
def profile():
    """Get user profile
    """
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": user.email}), 200
    abort(403)


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """Get password reset_token for a user
    """
    email = request.form.get("email")
    if email is not None:
        try:
            token = AUTH.get_reset_password_token(email=email)
            return jsonify(
                    {"email": email, "reset_token": token}), 200
        except ValueError:
            pass
    abort(403)


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """Update user password
    """
    email = request.form.get("email")
    token = request.form.get("reset_token")
    new_passwd = request.form.get("new_password")
    if all(itm is not None for itm in (email, token, new_passwd)):
        try:
            AUTH.update_password(reset_token=token, password=new_passwd)
            return jsonify(
                    {"email": email, "message": "Password updated"}), 200
        except ValueError:
            pass
    abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
