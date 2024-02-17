#!/usr/bin/env python3
"""
A basic auth class implementation
"""
from api.v1.auth.auth import Auth
from base64 import b64decode
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """
    a Basic auth class implementation
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        extract the base64 authorization header
        :param authorization_header:
        :return:
        """
        if not authorization_header or type(authorization_header) is not str:
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str) \
            -> str:
        """
        decode the base64 authorization header
        :param base64_authorization_header:
        :return:
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            encoded = base64_authorization_header.encode('utf-8')
            decoded64 = b64decode(encoded)
            decoded = decoded64.decode('utf-8')
        except BaseException:
            return None

        return decoded

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str) \
            -> (str, str):
        """
        extract the user credentials
        :param decoded_base64_authorization_header:
        :return:
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) != str:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None

        user_credentials = decoded_base64_authorization_header.split(':')
        if len(user_credentials) != 2:
            return None, None
        return user_credentials[0], user_credentials[1]

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        get the user object from the credentials
        :param user_email:
        :param user_pwd:
        :return:
        """
        if user_email is None or user_pwd is None:
            return None
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        try:
            found_users = User.search({'email': user_email})
        except Exception:
            return None

        for user in found_users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        get the current user
        :param request:
        :return:
        """
        if request is None:
            return None

        authorization_header = self.authorization_header(request)
        if authorization_header is None:
            return None

        base64_authorization_header = self.extract_base64_authorization_header(
            authorization_header)
        if base64_authorization_header is None:
            return None

        decoded_base64_authorization_header \
            = self. \
            decode_base64_authorization_header(base64_authorization_header)
        if decoded_base64_authorization_header is None:
            return None

        user_email, user_pwd = self.extract_user_credentials(
            decoded_base64_authorization_header)
        if user_email is None or user_pwd is None:
            return None

        user = self.user_object_from_credentials(user_email, user_pwd)
        if user is None:
            return None

        return user
