from json import dumps
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.user import UserHandler

from .base import BaseTest
import os

from .encryption_defs import encrypt_text, hash_pw, get_key, get_tokensalt, get_salt, get_emsalt
tokensalt = get_tokensalt()
key = get_key()
salt = get_salt()
salthex= salt.hex()
em_key = get_emsalt()
email_iv = os.urandom(12)
email_iv_hex = email_iv.hex()
display_iv = os.urandom(12)
display_iv_Hex = display_iv.hex()

class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/user', UserHandler)])
        super().setUpClass()

    async def register(self):
        await self.get_app().db.users.insert_one({
            'emailindex': hash_pw(self.email, em_key),
            'email': encrypt_text(self.email, key, email_iv),
            'emailiv': email_iv_hex,
            'password': hash_pw(self.password,salt),
            'passwordsalt': salthex,
            'displayName': encrypt_text(self.display_name, key, display_iv),
            'displayNameIV': display_iv.hex()
        })

    async def login(self):
        hashed_token = hash_pw(self.token, tokensalt)
        
        await self.get_app().db.users.update_one({
            'emailindex': hash_pw(self.email, em_key)
        }, {
            '$set': { 'token': hashed_token, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.token = 'testToken'
        self.display_name ='testDisplayName'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_user(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2['email'])
        self.assertEqual(self.display_name, body_2['displayName'])

    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})

        response = self.fetch('/user')
        self.assertEqual(400, response.code)
