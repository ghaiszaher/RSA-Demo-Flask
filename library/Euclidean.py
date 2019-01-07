#!/usr/bin/env python3
# encoding: utf-8

import time


def main():
    print('Py3')


def gcd_recursive(a, b):
    if b == 0:
        return abs(a)

    return gcd_recursive(abs(b), a % abs(b))


def gcd_repetitive(a, b):
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def gcd(a, b):
    return gcd_repetitive(a, b)


def test():
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))

    start_time = time.time()
    print("gcd_repetitive(", a, ",", b, ")=", gcd_repetitive(a, b))
    end_time = time.time()
    print("Time:", round((end_time - start_time) * 1000), "ms")

    start_time = time.time()
    print("gcd_recursive(", a, ",", b, ")=", gcd_recursive(a, b))
    end_time = time.time()
    print("Time:", round((end_time - start_time) * 1000), "ms")


###################

if __name__ == "__main__":
    test()
