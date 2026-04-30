from tornado.escape import json_decode

import os

from .base import BaseHandler
from .encryption_defs import hash_pw, encrypt_text, get_key, get_salt, get_emsalt

key = get_key()
pw_salt = get_salt()
em_salt = get_emsalt()

email_iv = os.urandom(12)
email_iv_hex = email_iv.hex()
display_iv = os.urandom(12)
display_iv_Hex = display_iv.hex()
address_iv = os.urandom(12)
address_iv_hex = address_iv.hex()
dob_iv = os.urandom(12)
dob_iv_hex = dob_iv.hex()
phonenumber_iv =os.urandom(12)
phonenumber_iv_hex = phonenumber_iv.hex()
disabilities_iv = os.urandom(12)
disabilities_iv_hex = disabilities_iv.hex()

class RegistrationHandler(BaseHandler):

    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            display_name = body.get('displayName')
            address = body.get('address')
            dob = body.get('dob')
            phonenumber = body.get('phonenumber')
            disabilities = body.get('disabilities')
            
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception('Display name must be a string')
        except Exception:
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

        user = await self.db.users.find_one({
          'emailindex': hash_pw(email, em_salt)
        })

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        email_blindex = hash_pw(email, em_salt)
        email_enc = encrypt_text(email, key, email_iv)
        hashed_passphrase = hash_pw(password,pw_salt)
        display_name_enc = encrypt_text(display_name, key, display_iv)
        address_enc = encrypt_text(address, key, address_iv)
        dob_enc = encrypt_text(dob, key, dob_iv)
        phonenumber_enc = encrypt_text(phonenumber, key, phonenumber_iv)
        disabilities_enc = encrypt_text(disabilities, key, disabilities_iv)
        
        await self.db.users.insert_one({
            'emailindex': email_blindex,
            'email': email_enc,
            'emailiv': email_iv_hex,
            'password': hashed_passphrase,
            'passwordsalt': pw_salt.hex(),
            'displayName': display_name_enc,
            'displayNameIV': display_iv_Hex,
            'address': address_enc,
            'addressiv': address_iv_hex,
            'dob': dob_enc,
            'dobiv': dob_iv_hex,
            'phonenumber': phonenumber_enc,
            'phonenumberiv': phonenumber_iv_hex,
            'disabilities': disabilities_enc,
            'disabilitiesiv': disabilities_iv_hex            
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()