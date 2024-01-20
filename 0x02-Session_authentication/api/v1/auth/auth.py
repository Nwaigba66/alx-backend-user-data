#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = os.getenv("AUTH_TYPE")
if auth == "basic_auth":
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()
elif auth == 'session_auth':
    from api.v1.auth.session_auth import SessionAuth
    auth = SessionAuth()
elif auth:
    from api.v1.auth.auth import Auth
    auth = Auth()

paths = [
        '/api/v1/status/', '/api/v1/unauthorized/', '/api/v1/forbidden/',
        '/api/v1/auth_session/login/']


@app.before_request
def before_request():
    """This will run before any request is processed
    """
    if auth and auth.require_auth(request.path, paths):
        if (
                not auth.authorization_header(request)
                and not auth.session_cookie(request)):
            abort(401)
        current_user = auth.current_user(request)
        if not current_user:
            abort(403)
        request.current_user = current_user


@app.errorhandler(403)
def forbidden(error) -> str:
    """ Forbidden handler
    """
    return jsonify({"error": "Forbidden"}), 403