#!/usr/bin/python
from matplotlib import pyplot, rc
import getopt, numpy, sys

optlist, args = getopt.getopt(sys.argv[1:], "", ["output=",
    "ylabel=", "xlabel="])

optdict = {}

for k,v in optlist:
  optdict[k] = v

output = "output.eps"
ylabel = "CDF"
xlabel = "Time in seconds"

if "--output" in optdict:
  output = optdict["--output"]

if "--ylabel" in optdict:
  ylabel = optdict["--ylabel"]

if "--xlabel" in optdict:
  xlabel = optdict["--xlabel"]

rc('font', **{'size' : 14})
markers = ['^', 's', 'o', 'v', '<', '>']
markers.reverse()
fig = pyplot.figure()

def cdf(data):
  data.sort()
  bins = {}
  for ent in data:
    if ent not in bins:
      bins[ent] = 0
    bins[ent] += 1

  binkeys = bins.keys()
  count = len(data) * 1.0
  binkeys.sort()
  x = []
  y = []
  last = 0
  for key in binkeys:
    x.append(key)
    last += bins[key]
    y.append(last / count)
  return x, y

for filename in args:
  x = numpy.loadtxt(filename, unpack=True)
  data = sorted(x)
  x, y = cdf(data)
  pyplot.plot(x, y, '-' + markers.pop(), label = filename)

pyplot.legend(loc = "lower right")
pyplot.subplots_adjust(bottom = .08, right = .98, top = .98, left = .08)
pyplot.ylabel(ylabel)
pyplot.xlabel(xlabel)
pyplot.savefig(output)
