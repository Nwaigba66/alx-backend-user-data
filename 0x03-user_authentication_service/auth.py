#!/usr/bin/env python3
"""Auth Module
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid


def _generate_uuid() -> str:
    """Generate string representation of uuid
    """
    return str(uuid.uuid4())


def _hash_password(password: str) -> bytes:
    """Hash a given password

    Arguments
    =========
    password: password to hash

    Returns: bytes representing hashed password

    >>> isinstance(_hash_password("adeyemi"), bytes)
    True
    """
    return bcrypt.hashpw(password.encode("utf-8"), salt=bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user.

        Args:
            email (str): User's email
            password (str): User's password

        Returns:
            User: Newly registered User object
        """
        try:
            # Check if the user already exists
            user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        # User doesn't exist, proceed with registration
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(
                    email=email,
                    hashed_password=hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Validate user login credentials.

        Args:
            email (str): User's email
            password (str): User's password

        Returns:
            bool: True if login is valid, False otherwise
        """
        try:
            # Locate user by email
            user = self._db.find_user_by(email=email)

            # Confirm password using bcrypt
            hashed_password = user.hashed_password
            provided_password = password.encode('utf-8')

            return bcrypt.checkpw(provided_password, hashed_password)

        except NoResultFound:
            # User not found
            return False

    def create_session(self, email: str) -> str:
        """Create a session for the user with given email
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = str(uuid.uuid4())
            user.session_id = session_id
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """Get user from a given session_id
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Remove session for a given user
        """
        try:
            user = self._db.find_user_by(id=user_id)
            user.session_id = None
        except NoResultFound:
            pass
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Get reset_password token for a user with an email
        """
        try:
            user = self._db.find_user_by(email=email)
            token = str(uuid.uuid4())
            user.reset_token = token
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Reset password of a user
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            user.hashed_password = _hash_password(password)
            user.reset_token = None
        except NoResultFound:
            raise ValueError
        return None
