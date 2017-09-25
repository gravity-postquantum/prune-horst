#!/usr/bin/env python

import parameters as p
import numpy as np
import matplotlib.pyplot as plt
import math

def log(x): return math.log(x,2)

QUANTUM = True

maxMessages = 4000
x = np.arange(50, maxMessages, 50)
y = [[],[],[]]

t = [2**17, 2**18, 2**19]
k = [54, 62, 64]
names = ['S', 'M', 'L']
colors = ['c','k','m']
handles = []

ax = plt.subplot()

for version in [0,1,2]:
    for v in x:
        nbMessages = int(v)
        bits = p.probForgAvrge(t[version], k[version], nbMessages)
        if QUANTUM:
            y[version].append(bits/2 + log(k[version]) - 2)
        else:
            y[version].append(bits + log(k[version]) - 2)
    h, = plt.plot(x, y[version], c=colors[version], label=names[version], linewidth=1)
    handles.append(h)

hlines = [64, 128, 256]
for h in hlines:
    ax.axhline(y=h, linestyle='dotted', c='k')
    ax.text(maxMessages - 400, h+5, str(h) )

plt.legend(handles=handles[::-1], loc=1)

if QUANTUM:
    plt.title('PRUNE-HORST security (quantum)')
else:
    plt.title('PRUNE-HORST security (classical)')
plt.xlabel('Number of messages signed')
plt.ylabel('Security level (bits)')

#plt.show()

plt.savefig('security.pdf')