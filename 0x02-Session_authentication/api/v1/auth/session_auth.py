#!/usr/bin/env python3
"""This module define the Session Auth class
"""
from .auth import Auth
import uuid
from models.user import User
from typing import TypeVar


class SessionAuth(Auth):
    """This class define the Session Authentication
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create a session
        """
        if not user_id or not isinstance(user_id, str):
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """get user_id for session_id
        """
        if not session_id or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> TypeVar(User):
        """Get the current user from session_id
        """
        session_cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_cookie)
        return User.get(user_id)

    def destroy_session(self, request=None) -> bool:
        """Delete session in a given request
        """
        if not request or not self.session_cookie(request):
            return False
        session_id = self.session_cookie(request)
        if not self.user_id_by_session_id.get(session_id):
            return False
        del self.user_id_by_session_id[session_id]
        return True
