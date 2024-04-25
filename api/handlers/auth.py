from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'displayName': 1,
            'expiresIn': 1,
            'encryptDisability': 1,
            'key': 1,
            'address': 1,
            'birthdate': 1,
            'phone': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return


        self.current_user = {}
        try:
            self.current_user['disability'] = user['encryptDisability']
            self.current_user['key'] = user['key']
            self.current_user['address'] = user['address']    
            self.current_user['birthdate'] = user['birthdate'] 
            self.current_user['phone'] = user['phone']   
        except KeyError:
            print('...............')
        self.current_user['email'] = user['email']
        self.current_user['display_name'] = user['displayName']
