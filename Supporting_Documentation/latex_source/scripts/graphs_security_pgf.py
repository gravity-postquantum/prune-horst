#!/usr/bin/env python

import parameters as p
import numpy as np
import matplotlib.pyplot as plt
import math

def log(x): return math.log(x,2)

QUANTUM = False

maxMessages = 4000
x = np.arange(50, maxMessages, 50)
y = [[],[],[]]

t = [2**17, 2**18, 2**19]
k = [54, 62, 64]
names = ['S', 'M', 'L']
colors = ['cyan','black','magenta']

output = r'''
\begin{tikzpicture}
  \begin{axis}[title=PRUNE-HORST security (%s),
    width=12cm,
    height=10cm,
    xlabel=Number of messages signed,
    ylabel=Security level (bits),
    ytick distance=50,
    xtick distance=500,
    xmin=1,
    xmax=4000,
    ymin=1,
    ymax=%u,
    x tick label style={
      /pgf/number format/.cd,
      set thousands separator={}
    }
  ]

\addplot[dashed,domain=1:4000,forget plot] {64};
\node[above] at (axis cs:3800,64){\scriptsize 64};

\addplot[dashed,domain=1:4000,forget plot] {128};
\node[above] at (axis cs:3800,128){\scriptsize 128};

\addplot[dashed,domain=1:4000,forget plot] {256};
\node[above] at (axis cs:3800,256){\scriptsize 256};
''' % ('quantum' if QUANTUM else 'classical', 300 if QUANTUM else 500)

for version in [2, 1, 0]:
    for v in x:
        nbMessages = int(v)
        bits = p.probForgAvrge(t[version], k[version], nbMessages)
        if QUANTUM:
            y[version].append(bits/2 + log(k[version]) - 2)
        else:
            y[version].append(bits + log(k[version]) - 2)
    output += r'\addplot[%s,thick] table {' % colors[version]
    output += '\nx y\n'
    output += '\n'.join(["%u %f" % (a, b) for a, b in zip(x, y[version])])
    output += '\n};\n'
    output += r'\addlegendentry{%s};' % names[version]
    output += '\n\n'

output += r'''
  \end{axis}
\end{tikzpicture}
'''
print output
