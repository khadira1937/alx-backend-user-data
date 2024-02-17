#!/usr/bin/env python3
"""
An authentication class
"""
from os import getenv

from flask import request
from typing import List, TypeVar


class Auth:
    """
    An authentication class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        require auth method
        :param path:
        :param excluded_paths:
        :return:
        """
        if not path or not excluded_paths:
            return True
        if path in excluded_paths:
            return False
        if path[-1] != '/' and path + '/' \
                in excluded_paths:
            return False
        for p in excluded_paths:
            if p.endswith('*') and \
                    path.startswith(p[:-1]):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        authorization header method
        :param request:
        :return:
        """
        if request is None:
            return None

        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        get the current user
        :param request:
        :return:
        """
        return None

    def session_cookie(self, request=None):
        """
        get the session cookie
        :param request:
        :return: cookie
        """
        if request is None:
            return None

        SESSION_NAME = getenv("SESSION_NAME")

        if SESSION_NAME is None:
            return None

        session_id = request.cookies.get(SESSION_NAME)

        return session_id
