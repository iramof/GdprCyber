import bcrypt

from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest

from api.handlers.login import LoginHandler

import urllib.parse

class LoginHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/login', LoginHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
      #Hash password
      salt = bcrypt.gensalt() # Generate salt
      hashed_password = bcrypt.hashpw(self.password.encode('utf-8'), salt)  # Hash the password with salt
      yield self.get_app().db.users.insert_one({
          'email': self.email,
          'password': hashed_password,
          'salt': salt,
          'displayName': 'testDisplayName',
          'encryptDisability': 'walk',
          'address': "Test Address",
          'birthdate': "20 March",
          'phone': "3538740"
      })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword_000'

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {
          'email': self.email,
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_case_insensitive(self):
        body = {
          'email': self.email.swapcase(),
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
          'email': 'wrongUsername',
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
          'email': self.email,
          'password': 'wrongPassword'
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)
