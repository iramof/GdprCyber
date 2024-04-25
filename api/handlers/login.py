import bcrypt
from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4

from .base import BaseHandler

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {
          'password': 1,
          'salt': 1
        })

        #print("the salt value is :", user.get('salt'), "....the stored password is :", user["password"])
        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        # Convert the entered password to bytes
        password_entered_bytes = password.encode('utf-8')

        # Check if the stored password is bytes or string
        if isinstance(user.get('password'), bytes):
            if not bcrypt.checkpw(password_entered_bytes, user.get('password')):
                self.send_error(403, message='The email address and password are invalid!')
                return
        else:
            # Assuming stored password is a string
            # Compare hashed password string with entered password
            hashed_entered_password = bcrypt.hashpw(password_entered_bytes, user.get('salt'))  # Hash the password with salt
            if hashed_entered_password != user.get('password').encode('utf-8'):
                self.send_error(403, message='The email address and password are invalid!')
                return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
