from tornado.web import authenticated
from cryptography.fernet import Fernet

from .auth import AuthHandler

class UserHandler(AuthHandler):


    def decryptData(self, data_to_decrypt, key):
        enc_key = key
        f = Fernet(enc_key)
        decrypted_data = f.decrypt(data_to_decrypt)
        return decrypted_data.decode()


    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']

        
        try:
            display_name = self.decryptData(self.current_user['display_name'], self.current_user['key'])
            self.response['displayName'] = display_name
            disability = self.decryptData(self.current_user['disability'], self.current_user['key'])
            self.response['disability'] = disability
            address = self.decryptData(self.current_user['address'], self.current_user['key'])
            self.response['address'] = address
            birthdate = self.decryptData(self.current_user['birthdate'], self.current_user['key'])
            self.response['birthdate'] = birthdate
            phone = self.decryptData(self.current_user['phone'], self.current_user['key'])
            self.response['phone'] = phone
        except KeyError:
            print('..............')
        self.write_json()
