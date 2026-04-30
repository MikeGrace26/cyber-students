from json import dumps
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.logout import LogoutHandler

import os

from .base import BaseTest
from .encryption_defs import hash_pw, get_tokensalt, get_salt, get_key, get_emsalt, encrypt_text

tokensalt = get_tokensalt()
salt = get_salt()
salthex= salt.hex()
key = get_key()
em_key = get_emsalt()
email_iv = os.urandom(12)
email_iv_hex = email_iv.hex()
display_iv = os.urandom(12)
display_iv_Hex = display_iv.hex()


class LogoutHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/logout', LogoutHandler)])
        super().setUpClass()

    async def register(self):
        await self.get_app().db.users.insert_one({
            'emailindex': hash_pw(self.email, em_key),
            'email': encrypt_text(self.email, key, email_iv),
            'emailiv': email_iv_hex,
            'password': hash_pw(self.password,salt),
            'passwordsalt': salthex,
            'displayName': encrypt_text('testDisplayName', key, display_iv),
            'displayNameIV': display_iv.hex()
        })

    async def login(self):
        hashed_token = hash_pw(self.token, tokensalt)    
        
        await self.get_app().db.users.update_one({
            'emailindex': hash_pw(self.email, em_key),
        }, {
            '$set': { 'token': hashed_token, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.token = 'testToken'
        
        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_logout(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

    def test_logout_without_token(self):
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_twice(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(403, response_2.code)
