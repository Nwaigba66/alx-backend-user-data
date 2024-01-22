#!/usr/bin/env python3
"""This module define a new view for Session Authentication
"""
from flask import jsonify, request, abort
from api.v1.views import app_views
from models.user import User
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> str:
    """ POST /api/v1/auth_session/login
    Return:
      - status of the login
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    try:
        users = User.search(dict(email=email))
        if not users:
            raise Exception
        for usr in users:
            if usr.is_valid_password(password):
                from api.v1.app import auth
                session_id = auth.create_session(usr.id)
                resp = jsonify(usr.to_json())
                resp.set_cookie(os.getenv("SESSION_NAME"), session_id)
                return resp
        return jsonify({"error": "wrong password"}), 401
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404


@app_views.route(
        '/auth_session/logout', methods=['DELETE'],
        strict_slashes=False)
def logout() -> str:
    """ DELETE /api/v1/auth_session/logout
    logout the user
    """
    from api.v1.app import auth
    logged_out = auth.destroy_session(request)
    if not logged_out:
        abort(404)

    return jsonify({}), 200
