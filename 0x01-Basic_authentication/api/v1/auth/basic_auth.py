#!/usr/bin/env python3
"""This module define the BasicAuth class
"""
from .auth import Auth
import base64
from models.user import User
from typing import List, TypeVar
from flask import request


class BasicAuth(Auth):
    """The Basic Authentication class
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Extract base64 auth from the auth header
        """
        auth_hdr = authorization_header
        if not auth_hdr or not isinstance(auth_hdr, str):
            return None
        if not auth_hdr.startswith("Basic "):
            return None
        return auth_hdr[auth_hdr.index(" ") + 1:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decode the base64 auth header"""
        b64_auth = base64_authorization_header
        if b64_auth is None or not isinstance(b64_auth, str):
            return None
        try:
            return base64.b64decode(b64_auth).decode("utf-8")
        except Exception:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> (str, str):
        """Extract the user credentials from decoded auth header
        """
        dec_b64 = decoded_base64_authorization_header
        if not dec_b64 or not isinstance(dec_b64, str) or ":" not in dec_b64:
            return (None, None)
        colon_index = dec_b64.index(":")
        return (dec_b64[:colon_index], dec_b64[colon_index + 1:])

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """Retrive the current user object from credentials
        """
        if not user_email or not user_pwd:
            return None
        if not all(isinstance(itm, str) for itm in (user_email, user_pwd)):
            return None
        users = ''

        try:
            users = User.search(dict(email=user_email))
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Get the current loggedin user
        """
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None
        base64_extract = self.extract_base64_authorization_header(
                auth_header)
        if not base64_extract:
            return None
        decoded_auth = self.decode_base64_authorization_header(
                base64_extract)
        if not decoded_auth:
            return None
        credentials = self.extract_user_credentials(decoded_auth)
        if not any(credentials):
            return None
        user = self.user_object_from_credentials(*credentials)
        return user
