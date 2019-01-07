#!/usr/bin/env python3
# encoding: utf-8


# Assuming that exponent is a power of 2
def fast_exp_pow2(base, exponent, modulus):
    if exponent == 0:
        return 1

    res = base % modulus
    i = 2
    while i <= exponent:
        res = res ** 2 % modulus
        i *= 2

    return res


def test():
    while True:
        base = int(input("Enter base: "))
        exponent = int(input("Enter exponent (pow of 2): "))
        modulus = int(input("Enter modulus: "))
        if base == 0 and exponent == 0 and modulus == 0:
            print("Exiting...")
            break
        print("Result:", fast_exp_pow2(base, exponent, modulus))
        print("-" * 20)


###################

if __name__ == "__main__":
    test()
