#!/usr/bin/env python3
# encoding: utf-8

import time


def beautify_time(seconds):
    if seconds < 1:
        return '%f milliseconds' % (seconds * 1000)
    return '%f seconds' % seconds


def timed_function_beautified(func, *args):
    res, t = timed_function(func, *args)
    return res, beautify_time(t)


def timed_function(func, *args):
    """
    Returns a tuple:
    (function's result , time needed in seconds)
    if the function doesn't return anything, first argument will be None
    """
    t1 = time.time()
    if len(args):
        res = func(*args)
    else:
        res = func()

    t2 = time.time()

    return res, t2 - t1


def test():
    res = timed_function(pow, 1021893, 2131930, 2003218291)
    print("Result is: %d" % res[0])
    print("Time needed: %s" % res[1])

    res = timed_function_beautified(pow, 1021893, 2131930, 2003218291)
    print("Beautified - Result is: %d" % res[0])
    print("Beautified - Time needed: %s" % res[1])


###################

if __name__ == "__main__":
    test()
