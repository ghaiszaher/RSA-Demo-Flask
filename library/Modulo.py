#!/usr/bin/env python3
# encoding: utf-8

import time


def pow_mod_normal(base, exponent, modulus):
    return (base ** exponent) % modulus


def pow_mod_binary(base, exponent, modulus):
    res = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:
            res = (res * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return res


def pow_mod_memory_efficient(base, exponent, modulus):
    if modulus == 1:
        return 0

    res = 1
    for eprime in range(0, exponent):
        res = (res * base) % modulus

    return res


def mult_mod(numbers, modulus):
    res = 1
    for n in numbers:
        res = (res * n) % modulus

    return res


def sum_mod(numbers, modulus):
    res = 0
    for n in numbers:
        res = (res + n) % modulus

    return res


def test():
    base = int(input("Enter base:"))
    exp = int(input("Enter exp:"))
    mod = int(input("Enter mod:"))

    print(base, "^", exp, " % ", mod, sep="")

    start_time = time.time()
    res = pow(base, exp, mod)
    end_time = time.time()
    print("-" * 10)
    print("Python Result:", res)
    print("Time:", round((end_time - start_time) * 1000), "ms")

    # start_time = time.time()
    # res = pow_mod_normal(base, exp, mod)
    # end_time = time.time()
    # print("-" * 10)
    # print("Normal Result:", res)
    # print("Time:", round((end_time - start_time) * 1000), "ms")

    start_time = time.time()
    res = pow_mod_binary(base, exp, mod)
    end_time = time.time()
    print("-" * 10)
    print("Binary Result:", res)
    print("Time:", round((end_time - start_time) * 1000), "ms")

    start_time = time.time()
    res = pow_mod_memory_efficient(base, exp, mod)
    end_time = time.time()
    print("-" * 10)
    print("Memory Efficient Result:", res)
    print("Time:", round((end_time - start_time) * 1000), "ms")

    print("#" * 20)
    l = [1, 2, 3, 4, 5, 6, 7];
    mod = 55
    print("mult({}) mod {} = {}".format(l, mod, mult_mod(l, mod)))
    print("sum({}) mod {} = {}".format(l, mod, sum_mod(l, mod)))


###################

if __name__ == "__main__":
    test()
