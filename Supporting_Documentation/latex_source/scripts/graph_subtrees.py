#!/usr/bin/env python

import numpy as np
import matplotlib.pyplot as plt
import math

t = [2**17, 2**18, 2**19]
k = [54, 62, 64]
names = ['S', 'M', 'L']
colors = ['c','k','m']
handles = []

logcrange = range(8)[1:]

pklens = [ 32*2**logc for logc in logcrange]
siglens = [[],[],[]]

def pklen(c):
    return 32*c

def siglen(t,k,logc):
    return 32*(k + k*(math.log(t,2) - logc) + 1)

ax = plt.subplot()


for version in [0,1,2]:
    for logc in logcrange:
        siglens[version].append( siglen(t[version],k[version],logc))
    h, = plt.plot(pklens, siglens[version], c=colors[version], label=names[version], linewidth=1)
    handles.append(h)
    plt.scatter(pklens, siglens[version], s=10, c=colors[version], label=names[version])

# add optimal C for each version
pkoptimal = [ pklen(2**6), pklen(2**7), pklen(2**7) ]
sigoptimal = [
        siglen(t[0],k[0],6),
        siglen(t[1],k[1],7),
        siglen(t[2],k[2],7),
]
for version in [0,1,2]:
    plt.scatter([pkoptimal[version]], [sigoptimal[version]], s=80, c=colors[version], marker='*')

plt.legend(handles=handles[::-1], loc=1)

plt.title('Trade-offs signature length / public key length')
plt.xlabel('Public key bytes')
plt.ylabel('Signature bytes')

ax.set_xlim([0, 32*2**7 + 100])

plt.grid()
#plt.show()

plt.savefig('subtrees.pdf')