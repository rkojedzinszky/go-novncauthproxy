#!/usr/bin/python

import json
import time
import argparse
from jwcrypto import jwt, jwk

def create_token(args: object) -> str:
    claims = {
        'vnc': {
            'a': args.vncaddress,
            'p': args.vncpassword,
        },
        'exp':  int(time.time() + args.expiry),
    }

    if args.subject != '':
        claims['sub'] = args.subject

    if args.audience != '':
        claims['aud'] = args.audience

    key = jwk.JWK(kty="oct", k=args.jwe_key)
    token = jwt.JWT(claims=claims, header={"alg":"A256KW", "enc":"A256CBC-HS512"})
    token.make_encrypted_token(key)
    
    return token.serialize()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--jwe-key", type=str, required=True, help="Key used to encrypt JWE token. Must be 32 bytes length, encoded in base64")
    parser.add_argument("--vncaddress", type=str, required=True, help="VNC Server address")
    parser.add_argument("--vncpassword", type=str, help="VNC Server password")
    parser.add_argument("--expiry", type=int, default=5, help="Expiry time in seconds")
    parser.add_argument("--subject", type=str, default='', help="JWE Token subject (sub)")
    parser.add_argument("--audience", type=str, default='', help="JWE Token audience (aud)")

    args = parser.parse_args()

    token = create_token(args)

    print ("Token=", token)