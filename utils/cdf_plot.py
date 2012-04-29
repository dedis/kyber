#!/usr/bin/python
from matplotlib import pyplot, rc
#from scipy.stats import cumfreq
#from statsmodels.tools.tools import ECDF
import getopt, math, numpy, sys

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
  last_key = 0
  for key in binkeys:
    x.append(last_key)
    last_key = key
    x.append(key)
    last += bins[key]
    y.append(last / count)
    y.append(last / count)
  return x, y

"""
def cdf0(data):
  num_bins = math.sqrt(len(data))
  cf = cumfreq(data, num_bins)
  x = numpy.linspace(min(data), max(data), num_bins)
  return x, (cf[0] * 1.0) / (1.0 * cf[0][-1])
"""

"""
def cdf1(data):
  num_bins = math.sqrt(len(data))
  ecdf = ECDF(data)
  x = numpy.linspace(min(data), max(data), num_bins)
  y = ecdf(x)
  return x, y
"""

intensity_addend = 1.0 / len(args)
intensity = 0
marker_count = 5
plot = pyplot.semilogx

for filename in args:
  data = numpy.loadtxt(filename, unpack=True)
  x, y = cdf(data)

  x0 = []
  y0 = []
  x0.append(x[1])
  y0.append(y[1])

  inc = len(x) / marker_count
  current = 1 + inc
  for idx in range(marker_count - 1):
    x0.append(x[current])
    y0.append(y[current])
    current += inc

  x0.append(x[-2])
  y0.append(y[-2])

  plot(x, y, "-", label = filename, **{"color" : str(intensity)})
  plot(x0, y0, markers.pop(), **{"color" : str(intensity)})

  intensity += intensity_addend

pyplot.legend(loc = "lower right")
pyplot.subplots_adjust(bottom = .12, right = .98, top = .98, left = .08)
pyplot.ylabel(ylabel)
pyplot.xlabel(xlabel)
pyplot.savefig(output)
