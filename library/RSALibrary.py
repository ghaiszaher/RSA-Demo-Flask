#!/usr/bin/env python3
# encoding: utf-8

import random
import Euclidean
import PrimalityTests
import Modulo
import ExtendedEuclidean
import math
import StringLibrary
import TimeLibrary


# following miller-rabin test
def is_primary(n):
    l = [2, 3]
    if n < 2:
        return False
    if n in [2,3,5,7,11]:
        return True
    bits = math.ceil(math.log2(n))
    if bits < 2:
        return False
    l.append(random.getrandbits(bits // 2))
    l.append(random.getrandbits(bits // 2))
    l.append(random.getrandbits(bits // 2))

    for a in l:
        if PrimalityTests.is_composite_miller_rabin(n, a):
            return False

    return True


def generate_random_primary(bits=512):
    max_iter = 5000
    while True:
        rnd = random.getrandbits(bits)
        if is_primary(rnd):
            return rnd

        max_iter -= 1
        if max_iter <= 0:
            raise Exception("Cannot find a primary number")


def generate_public_key_e(phi, min_value=3):
    if min_value % 2 == 0:
        min_value += 1
    for i in range(min_value, phi, 2):
        if Euclidean.gcd(i, phi) == 1:
            return i
    raise Exception("Couldn't find E!")


def compute_private_key_d(e, phi):
    g, x, y = ExtendedEuclidean.extended_euclidean(e, phi)

    d = x % phi
    return d


def generate_keys(bits=512, min_e_value=3, return_p_q=False):
    p = generate_random_primary(bits)
    q = generate_random_primary(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = generate_public_key_e(phi, min_value=min_e_value)
    d = compute_private_key_d(e, phi)
    if return_p_q:
        return n, e, d, p, q
    return n, e, d


def encrypt_number(n, e, number):
    if number >= n or number < 0:
        raise Exception("Number should be greater than 0 and less than N")

    return Modulo.pow_mod_binary(number, e, n)


def decrypt_number(n, d, cipher_number):
    return encrypt_number(n, d, cipher_number)


def decrypt_number_crt(d, p, q, cipher_number):
    n = p * q
    mp = Modulo.pow_mod_binary(cipher_number, d % (p - 1), p)
    mq = Modulo.pow_mod_binary(cipher_number, d % (q - 1), q)

    g, yp, yq = ExtendedEuclidean.extended_euclidean(p, q)

    m = (Modulo.mult_mod([mp, yq, q], n) + Modulo.mult_mod([mq, yp, p], n)) % n

    return m


def encrypt_text(n, e, text):
    l = []
    for c in text:
        l.append(encrypt_number(n, e, ord(c)))

    return l


def decrypt_text(n, d, cipher_text_list):
    s = ""
    for cipher_number in cipher_text_list:
        o = decrypt_number(n, d, cipher_number)
        s += chr(o)

    return s


def encrypt_text_to_text(n, e, text, sep='|'):
    l = encrypt_text(n, e, text)
    l = [str(n) for n in l]
    return sep.join(l)


def decrypt_text_from_text(n, d, cipher_text, sep='|'):
    l = cipher_text.split(sep)
    l = [int(s) for s in l]
    return decrypt_text(n, d, l)


def encrypt_text_v2(n, e, text):
    if len(text) >= math.log2(n) / 8:  # length of the text is more than the number of bytes in N
        raise Exception("Text is longer than n({})".format(n))

    plain = StringLibrary.text_to_integer(text)
    return encrypt_number(n, e, plain)


def decrypt_text_v2(n, d, cipher_number):
    if cipher_number >= n:
        raise Exception("Cipher number({}) is longer than n({})".format(cipher_number, n))

    plain = decrypt_number(n, d, cipher_number)
    return StringLibrary.integer_to_text(plain)


def test():
    print("Generating keys...")
    n, e, d, p, q = generate_keys(bits=512, min_e_value=3, return_p_q=True)
    print("n=", n)
    print("e=", e)
    print("d=", d)
    print('-' * 20)

    print("Encrypting a number:")
    number = random.getrandbits(8)
    print("Number to send:", number)

    cipher_number = encrypt_number(n, e, number)
    print("Cipher:", cipher_number)

    decrypted = decrypt_number(n, d, cipher_number)
    print("Decrypted:", decrypted)

    decrypted_crt = decrypt_number_crt(d, p, q, cipher_number)
    print("Decrypted using CRT:", decrypted_crt)

    print('-' * 20)
    print("Normal vs CRT performance:")

    try:
        ts_normal = 0
        ts_crt = 0
        for i in range(300, 1000):
            _, t = TimeLibrary.timed_function(decrypt_number, n, d, cipher_number)
            ts_normal += t
            _, t = TimeLibrary.timed_function(decrypt_number_crt, d, p, q, cipher_number)
            ts_crt += t

        print("Total time for normal:", TimeLibrary.beautify_time(ts_normal))
        print("Total time for CRT:", TimeLibrary.beautify_time(ts_crt))
        print("Rate: %f times" % (ts_normal / ts_crt))
    except:
        print("Failed!")
        pass

    print('-' * 20)

    print("Encrypting a text:")
    text = "This is a test message..."
    print("Text to send:", text)

    cipher_text = encrypt_text(n, e, text)
    print("Cipher Text:", cipher_text)

    decrypted = decrypt_text(n, d, cipher_text)
    print("Decrypted Text:", decrypted)
    print('-' * 20)

    print("Encrypting a text to text:")
    text = "Another text message!"
    print("Text to send:", text)

    cipher_text = encrypt_text_to_text(n, e, text)
    print("Cipher Text:", cipher_text)

    decrypted = decrypt_text_from_text(n, d, cipher_text)
    print("Decrypted Text:", decrypted)

    print('-' * 20)
    print("Encrypting a text to number (v2):")
    text = "This third text is going to be encrypted to a single number."
    print("Text to send:", text)

    cipher_number = encrypt_text_v2(n, e, text)
    print("Cipher Number:", cipher_number)

    decrypted = decrypt_text_v2(n, d, cipher_number)
    print("Decrypted text:", decrypted)


###################

if __name__ == "__main__":
    test()
