#!/usr/bin/env python3
# encoding: utf-8


import sys

sys.path.append('../library')
import RSALibrary


def test():
    print("Generating Keys...")
    (n, e, d) = RSALibrary.generate_keys()

    print("n:", n)
    print("e:", e)
    print("d:", d)
    print("-" * 20)

    message = input("Enter a message to send:")
    signature = RSALibrary.encrypt_text_v2(n, d, message)

    print("message:", message)
    print("signature:", signature)

    print("-" * 10)

    print("---- Bob -----")
    received_message = input("Enter the received message:")
    received_signature = int(input("Enter the received signature:"))
    if RSALibrary.decrypt_text_v2(n,e,received_signature) == received_message:
        print("Yes, Alice is the sender.")
    else:
        print("No, Alice is not the sender!")

###################

if __name__ == "__main__":
    test()
