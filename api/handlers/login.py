from datetime import datetime, timedelta, timezone
from tornado.escape import json_decode
from uuid import uuid4

from .base import BaseHandler
from .encryption_defs import hash_pw, get_key, get_emsalt, get_tokensalt

key = get_key()
em_salt = get_emsalt()
tokensalt = get_tokensalt()

class LoginHandler(BaseHandler):

    async def generate_token(self, emailindex):
        token_uuid = uuid4().hex
        hashed_token = hash_pw(token_uuid,tokensalt)
        expires_in = (datetime.now(timezone.utc) + timedelta(hours=2)).timestamp()

        token_hashed = {
            'token': hashed_token,
            'expiresIn': expires_in,
        }
        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }
        await self.db.users.update_one({
            'emailindex': emailindex
        }, {
            '$set': token_hashed
        })

        return token

    async def post(self):
        
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            
        except Exception:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = await self.db.users.find_one({
          'emailindex': hash_pw(email, em_salt)
        }, {
          'emailindex': 1, 'email': 1, 'emailiv': 1, 'password': 1, 'passwordsalt': 1,
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        salt_hex = user['passwordsalt']
        salt= bytes.fromhex(salt_hex)
        hashed_passphrase = hash_pw(password, salt)
        emailindex = user['emailindex']

        if user['password'] != hashed_passphrase:
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = await self.generate_token(emailindex)

        self.set_status(200)
        self.response['token'] = token ['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()