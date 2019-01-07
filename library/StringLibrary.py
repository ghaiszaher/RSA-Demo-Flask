#!/usr/bin/env python3
# encoding: utf-8


def text_to_integer(text):
    res = 0
    for c in text:
        if ord(c) > 255:
            raise Exception("Character {} is not a byte".format(c))
        res <<= 8
        res += ord(c)

    return res


def integer_to_text(n):
    res = ''
    while n > 0:
        c = n & 0xFF
        res = chr(c) + res
        n >>= 8
    return res


def test():
    t = input("Enter text: ")
    print("Integer value:")
    print(text_to_integer(t))
    print("-" * 20)
    n = int(input("Enter integer: "))
    print("Text value:")
    print(integer_to_text(n))


if __name__ == "__main__":
    test()
