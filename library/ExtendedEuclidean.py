#!/usr/bin/env python3
# encoding: utf-8

import time


def extended_euclidean(a, b):
    r, q, x, y = [], [], [], []

    r[0:2] = [a, b]
    x[0:2] = [1, 0]
    y[0:2] = [0, 1]
    q[0:] = [0]
    k = 1

    while True:
        r[k + 1:] = [r[k - 1] % r[k]]
        if r[k + 1] == 0:
            break
        q[k:] = [r[k - 1] // r[k]]
        x[k + 1:] = [-x[k] * q[k] + x[k - 1]]
        y[k + 1:] = [-y[k] * q[k] + y[k - 1]]

        k += 1

    return r[k], x[k], y[k]


def test():
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))

    start_time = time.time()
    g, x, y = extended_euclidean(a, b)
    end_time = time.time()
    print("extended_euclidean(", a, ",", b, ")=", g, sep='')
    print("x=", x)
    print("y=", y)
    print("a*x + b*y = g")
    print(a,"*",x," + ",b,"*",y," = ", g, sep='')
    print("Time:", round((end_time - start_time) * 1000), "ms")


###################

if __name__ == "__main__":
    test()
