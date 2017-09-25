#!/usr/bin/env python

import math
import sys

t = 2**19
k = 2**5
maxMessages = 128

def log2(x):
    return math.log(x,2)

def probForgWorst(t, k, maxMessages):
    maxKeys = maxMessages * k
    logProb = (log2(t) - log2(maxKeys))*k
    if logProb < 0:
        print("t too low for worst-case forgery prob")
        return 0
    return logProb

# https://math.stackexchange.com/questions/72223/finding-expected-number-of-distinct-values-selected-from-a-set-of-integers
def probForgAvrge(t, k, maxMessages):
    choices = maxMessages * k
    logAvgDistinct = log2(t**choices - (t-1)**choices) - (choices-1)*log2(t)
    logProb = (log2(t) - logAvgDistinct)*k
    return logProb


# finds the optimal trade-off for the key length,
# storing all nodes at level x, only giving paths 
# for lower levels
def sigLen(n, k):
    logn = log2(n)
    best = k*(logn + 1) 
    bestx = 0
    for x in range(int(logn) -1)[2:]:
        new = k*(logn -x +1) + 2**x
        if new <= best:
            best = new
            bestx = x
    print("best x: %d" % bestx)
    siglen = k*(logn -bestx +1) + 1 #+ 2**bestx
    print("sig len: %d hashes (%d bytes, %.2fKB)" % (siglen, siglen*32, siglen*32/1024) )
    print("pk len: %d hashes (%d bytes, %.2fKB)" % (2**bestx, (2**bestx)*32, (2**bestx)*32/1024))

def main():
    global t, k, maxMessages

    if len(sys.argv) == 4:
        t = 2**int(sys.argv[1])
        k = int(sys.argv[2])
        maxMessages = int(sys.argv[3])
    else:
        print("usage: %s log2(t) k maxMessages" % sys.argv[0])
        sys.exit(1)

    print("log t = %d" % log2(t))
    print("k = %d" % k)
    print("maxMessages  = %d" % maxMessages)
    logProbWorst = probForgWorst(t, k, maxMessages)
    logProbAvrge = probForgAvrge(t, k, maxMessages)

    print("prob(forgery, worst-case) = 2^-%.2f" % logProbWorst)
    print("prob(forgery, avrge-case) = 2^-%.2f" % logProbAvrge)

    clsec = logProbAvrge + log2(k) -2
    pqsec = logProbAvrge/2 + log2(k) - 2
    print("cl security ~ %.2f" % clsec)
    print("pq security > %.2f" % pqsec)

    sigLen(t, k)


if __name__ == "__main__": 
    main()
