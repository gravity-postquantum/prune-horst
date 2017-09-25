#!/usr/bin/env python

import numpy as np
import matplotlib.pyplot as plt
import math

t = [2**17, 2**18, 2**19]
k = [54, 62, 64]
names = ['S', 'M', 'L']
colors = ['cyan','black','magenta']
handles = []

logcrange = range(8)[1:]

pklens = [ 32*2**logc for logc in logcrange]
siglens = [[],[],[]]

def pklen(c):
    return 32*c

def siglen(t,k,logc):
    return 32*(k + k*(math.log(t,2) - logc) + 1)


print r'''
\begin{tikzpicture}
  \begin{axis}[title=Tradeoffs signature length / public key length,
    width=12cm,
    height=10cm,
    xlabel=Public key bytes,
    ylabel=Signature bytes,
    ytick distance=5000,
    xtick distance=500,
    xmin=0,
    xmax=4192,
    ymin=15000,
    ymax=45000,
    x tick label style={
      /pgf/number format/.cd,
      set thousands separator={}
    },
    scaled y ticks=false,
    y tick label style={
      /pgf/number format/.cd,
      set thousands separator={}
    },
    grid style={help lines,dotted},
    grid=major
  ]
'''

for version in [2, 1, 0]:
    for logc in logcrange:
        siglens[version].append( siglen(t[version],k[version],logc))
    print r'''\addplot[%s,mark=*] coordinates {''' % ( colors[version] )
    print '\n'.join(['(%u, %f)' % (a, b) for a, b in zip(pklens, siglens[version])])
    print '};'
    print r'\addlegendentry{%s};' % names[version]


# add optimal C for each version
pkoptimal = [ pklen(2**6), pklen(2**7), pklen(2**7) ]
sigoptimal = [
        siglen(t[0],k[0],6),
        siglen(t[1],k[1],7),
        siglen(t[2],k[2],7),
]

for version in [2, 1, 0]:
    print r'''\addplot[only marks,mark=triangle*,mark size=4pt,%s] coordinates {''' % colors[version]
    print '(%u, %f)' % (pkoptimal[version], sigoptimal[version])
    print '};'

print r'''
  \end{axis}
\end{tikzpicture}
'''
