#!/usr/bin/env python3
"""
Session Auth Class
"""

from .auth import Auth
import uuid
from models.user import User


class SessionAuth(Auth):
    """ Session Auth Class
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ Create Session ID for a user_id
        """
        if user_id is None or type(user_id) is not str:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        :param session_id:
        :return: User ID based on session id
        """
        if session_id is None or type(session_id) is not str:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        :param request:
        :return: User object based on cookie value
        """
        if request is None:
            return None
        session_id = self.session_cookie(request)
        if session_id is None:
            return None
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return None
        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        """
        destroy session method
        :param request:
        :return:
        """
        if request is None:
            return False
        if self.session_cookie(request) is None:
            return False

        if not self.user_id_for_session_id(self.session_cookie(request)):
            return False
        if self.session_cookie(request) in self.user_id_by_session_id:
            del self.user_id_by_session_id[self.session_cookie(request)]
        return True
