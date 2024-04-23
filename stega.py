import os
import argparse
import base64
import sys
import functools
from io import BytesIO
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-g', '--keygen', action='store_true')
    group.add_argument('-e', '--encrypt-key', type=argparse.FileType('r', encoding='ascii'))
    group.add_argument('-d', '--decrypt-key', type=argparse.FileType('r', encoding='ascii'))
    parser.add_argument('-f', '--force', action='store_true')
    parser.add_argument('-i', '--in-place', action='store_true')
    parser.add_argument('-b', '--base64', action='store_true')
    parser.add_argument('-m', '--html', action='store_true')

    parser.add_argument('files', nargs='*', type=argparse.FileType('rb'))
    return parser.parse_args()


NONCE_SIZE = TAG_SIZE = 16
KEY_SIZE = 32
args = parse_args()


@functools.cache
def html_template():
    with open(os.path.join(os.path.dirname(__file__), 'index.html'), 'rb') as fp:
        c = fp.read()
    pat = b'%CIPHER_TEXT%'
    i = c.index(pat)
    before = c[:i]
    after = c[i + len(pat):]
    return lambda x: before + x + after


def keygen():
    key = get_random_bytes(KEY_SIZE)
    sys.stdout.buffer.write(base64.b64encode(key).rstrip(b'='))
    sys.stdout.buffer.write(b'\n')


def b64decode(data: bytes):
    t = len(data) % 4
    if t:
        data += '=' * (4 - t)
    return base64.b64decode(data)


def write(fp_in: BytesIO, content: bytes):
    in_name = fp_in.name
    if args.in_place:
        c = 0
        while True:
            name = in_name + f'.{c}'
            try:
                file = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                c += 1
            else:
                break
    else:
        name = file = in_name + ('.enc' if args.encrypt_key else '.dec')
        if not args.force and os.path.exists(file):
            raise FileExistsError(file)

    with open(file, 'wb') as fp:
        fp.write(content)

    if args.in_place:
        os.replace(name, fp_in.name)


class Key:
    def __init__(self, fp_b64_key: BytesIO) -> None:
        self._key = b64decode(fp_b64_key.read().strip())

    def encrypt(self, fp: BytesIO):
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
        cipher_text, tag = cipher.encrypt_and_digest(fp.read())
        content = nonce + cipher_text + tag

        if args.html:
            content = base64.b64encode(content).rstrip(b'=')
            content = html_template()(content)
        elif args.base64:
            content = base64.b64encode(content).rstrip(b'=') + b'\n'

        write(fp, content)

    def decrypt(self, fp: BytesIO):
        if args.html:
            raise NotImplementedError

        content = fp.read()
        if args.base64:
            content = b64decode(content)

        nonce = content[:NONCE_SIZE]
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)

        cipher_text = content[NONCE_SIZE:-TAG_SIZE]
        tag = content[-TAG_SIZE:]
        content = cipher.decrypt_and_verify(cipher_text, tag)

        write(fp, content)


def main():
    if args.keygen:
        keygen()
        return

    if args.encrypt_key:
        handler = Key(args.encrypt_key).encrypt
    else:
        handler = Key(args.decrypt_key).decrypt

    for fp in args.files:
        try:
            handler(fp)
        finally:
            fp.close()
            print(fp.name, file=sys.stderr)


if __name__ == '__main__':
    main()
