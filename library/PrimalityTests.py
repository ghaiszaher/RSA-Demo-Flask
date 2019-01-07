#!/usr/bin/env python3
# encoding: utf-8

import time
import random
import Modulo


def is_primary_sieve(n):
    if n > 10000:
        print("Too big!")
        return False
    if n == 1:
        return False
    if n == 2:
        return True
    if not n & 1:  # even
        return False

    sieve = [True] * (n + 1)
    limit = int(n ** 0.5)
    for i in range(2, limit + 1):
        if not sieve[i]:
            continue
        for j in range(2, n + 1):
            index = i * j
            if index > n:
                break
            sieve[index] = False

    return sieve[n]


def is_composite_miller_rabin(n, a):
    if a>=n:
        print("a should be less than n")
        raise Exception("Miller Rabin Test: a should be less than n")
    d = n-1
    s = 0
    while d % 2 == 0: # d is even
        d //= 2
        s += 1

    # First step
    if Modulo.pow_mod_binary(a, d, n) == 1:
        return False
    minus_one = (-1) % n
    for r in range(0, s):
        if Modulo.pow_mod_binary(a, ((2 ** r) * d), n) == minus_one:
            return False

    return True


def test():
    n = int(input("Enter n: "))

    print("Sieve: ")
    start_time = time.time()
    sieve = is_primary_sieve(n)
    end_time = time.time()
    print("Prime" if sieve else "Not Prime")
    print("Time:", round((end_time - start_time) * 1000), "ms")

    print("-" * 10)

    print("Miller-Rabin Test: ")
    miller_rabin = False
    while not miller_rabin:
        a = int(input("Enter a (1 or less to quit): "))
        if a<2:
            break

        start_time = time.time()
        miller_rabin = is_composite_miller_rabin(n,a)
        end_time = time.time()
        print("Result (n=",n,",a=",a,"): ","Composite" if miller_rabin else "Not Sure", sep="")
        print("Time:", round((end_time - start_time) * 1000), "ms")

    print("-" * 10)


###################

if __name__ == "__main__":
    test()
