from tornado.web import authenticated

from .auth import AuthHandler
from .encryption_defs import decrypt_text, get_key

key = get_key()

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = decrypt_text(self.current_user['email'], key, bytes.fromhex(self.current_user['emailiv']))
        self.response['displayName'] = decrypt_text(self.current_user['display_name'], key, bytes.fromhex(self.current_user['displayNameIV']))
        self.write_json()