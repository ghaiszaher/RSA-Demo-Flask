#!/usr/bin/env python3
# encoding: utf-8


def fast_exp(base, exponent, modulus):
    res = 1
    binary = bin(exponent)[2:]
    y = base % modulus
    for b in reversed(binary):
        if b == '1':
            res = (res * y) % modulus
        y = (y ** 2) % modulus

    return res


def test():
    while True:
        base = int(input("Enter base: "))
        exponent = int(input("Enter exponent: "))
        modulus = int(input("Enter modulus: "))
        if base == 0 and exponent == 0 and modulus == 0:
            print("Exiting...")
            break
        print("Result:", fast_exp(base, exponent, modulus))
        print("-" * 20)


###################

if __name__ == "__main__":
    test()
