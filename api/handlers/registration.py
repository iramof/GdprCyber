from cryptography.fernet import Fernet
import bcrypt
from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

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
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            disability = body.get('disability')
            if not isinstance(disability, str):
                raise Exception()
            address = body.get('address')
            if not isinstance(address, str):
                raise Exception()
            birthDate = body.get('birthdate')
            if not isinstance(address, str):
                raise Exception()
            phone = body.get('phone')
            


        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        if not disability:
            self.send_error(400, message='The disability is invalid!')
            return

        if not address:
            self.send_error(400, message='The address is invalid!')
            return

        if not birthDate:
            self.send_error(400, message='The birth date is invalid!')
            return

        

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        #encrypt disability
        enc_key = Fernet.generate_key() #generate encryption key
        f = Fernet(enc_key)

        encrypted_disability = f.encrypt(disability.encode())
        encrypted_address = f.encrypt(address.encode())
        encrypted_birthdate = f.encrypt(birthDate.encode())
        encrypted_phone = f.encrypt(phone.encode())
        encrypted_display_name = f.encrypt(display_name.encode())


        #Hash password
        salt = bcrypt.gensalt() # Generate salt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)  # Hash the password with salt

        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password,
            'salt': salt,
            'displayName': encrypted_display_name,
            'encryptDisability': encrypted_disability,
            'key': enc_key,
            'address': encrypted_address,
            'birthdate': encrypted_birthdate,
            'phone': encrypted_phone
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.response['disability'] = disability
        self.response['address'] = address
        self.response['birth date'] = birthDate
        self.response['phone'] = phone

        self.write_json()