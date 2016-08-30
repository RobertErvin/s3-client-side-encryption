#!/usr/bin/env python3

# Copyright 2015, MIT license, github.com/tedder42.
# You know what the MIT license is, follow it.

# todo:
# - decrypt while "streaming" from s3/boto3, no intermediate file (and no hardcoded "decrypted-" filename)
# - ensure python2 compatability (if anyone cares)
# - integrate into boto3

import base64
import json
from Crypto.Cipher import AES # pycryptodome
import boto3
import uuid
import os

boto3.setup_default_session(profile_name='reinquire')

# decrypt_file method from: http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
# via: https://github.com/boto/boto3/issues/38#issuecomment-174106849
def decrypt_file(key, in_filename, iv, original_size, out_filename, chunksize=16*1024):
    with open(in_filename, 'rb') as infile:
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(original_size)

# s3_encryption reads everything into memory. we can avoid this if we add chunking (and file 'handles') to s3_encryption:
# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
# http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#highlighter_842384
# http://legrandin.github.io/pycryptodome/Doc/3.3.1/Crypto.Cipher._mode_cbc.CbcMode-class.html
# https://github.com/boldfield/s3-encryption/blob/08f544f06e7f86d5df978718d6b3958c2eebba6a/s3_encryption/handler.py#L39


def get_decrypted_file(bucket, key, dest_file):
    s3 = boto3.client('s3', region_name="us-east-1")
    object_info = s3.head_object(Bucket=bucket, Key=key)

    metadata = object_info['Metadata']

    envelope_key = base64.b64decode(metadata['x-amz-key-v2'])
    envelope_iv = base64.b64decode(metadata['x-amz-iv'])
    encrypt_ctx = json.loads(metadata['x-amz-matdesc'])
    original_size = metadata['x-amz-unencrypted-content-length']

    kms = boto3.client('kms', region_name="us-east-1")
    decrypted_envelope_key = kms.decrypt(CiphertextBlob=envelope_key,EncryptionContext=encrypt_ctx)

    temp_output_file = str(uuid.uuid4()) + '.csv'
    s3.download_file(bucket, key, temp_output_file)
    decrypt_file(decrypted_envelope_key['Plaintext'], temp_output_file, envelope_iv, int(original_size), dest_file)
    os.remove(temp_output_file)

