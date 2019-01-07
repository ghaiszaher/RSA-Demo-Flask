#!/usr/bin/env python3
# encoding: utf-8

import sys
sys.path.append('../library')
import RSALibrary


def pause():
    input("Press any key to continue...")


def main():
    print("\t1.Generate RSA keys for me")
    print("\t2.I already have RSA keys")
    choice = "0"
    while choice not in ("1", "2"):
        choice = input("Enter the choice: ")

    if choice == "1":
        n, e, d = RSALibrary.generate_keys(bits=512, min_e_value=3)
    else:
        n = int(input("Enter n: "))
        e = int(input("Enter e: "))
        d = int(input("Enter d: "))

    print("The key values:")
    print("n:", n)
    print("e:", e)
    print("d:", d)
    pause()
    print("-" * 30)
    while True:
        print("\t1. Encrypt a number")
        print("\t2. Decrypt a number")
        print("\t3. Encrypt a text")
        print("\t4. Decrypt a text")
        print("\t5. Encrypt a text to a single number")
        print("\t6. Decrypt a single number to text")
        print("\t0. It's enough")

        choice = input("Enter a choice: ")
        if choice == "1":
            p = int(input("Enter a NUMBER to Encrypt: "))
            c = RSALibrary.encrypt_number(n, e, p)
            print("The encrypted number is:", c)
            pause()
        elif choice == "2":
            c = int(input("Enter a number to Decrypt: "))
            p = RSALibrary.decrypt_number(n, d, c)
            print("The decrypted number is:", p)
            pause()
        elif choice == "3":
            p = input("Enter a text to Encrypt: ")
            c = RSALibrary.encrypt_text_to_text(n, e, p)
            print("The encrypted text is:", c)
            pause()
        elif choice == "4":
            c = input("Enter a text to Decrypt: ")
            p = RSALibrary.decrypt_text_from_text(n, d, c)
            print("The decrypted text is:", p)
            pause()
        elif choice == "5":
            p = input("Enter a text to Encrypt: ")
            c = RSALibrary.encrypt_text_v2(n, e, p)
            print("The encrypted text is:", c)
            pause()
        elif choice == "6":
            c = int(input("Enter a text to Decrypt: "))
            p = RSALibrary.decrypt_text_v2(n, d, c)
            print("The decrypted text is:", p)
            pause()
        elif choice == "0":
            break


###################

if __name__ == "__main__":
    main()
