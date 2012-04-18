#!/usr/bin/python
from datetime import datetime
import getopt
import math
import sys

optlist, args = getopt.getopt(sys.argv[1:], "", ["output_base="])

optdict = {}

for k,v in optlist:
  optdict[k] = v

output_base = None
if "--output_base" in optdict:
  output_base = optdict["--output_base"]

rounds_to_ignore = { }
starting_time = None

def time_parse0(str_time):
  return datetime.strptime(str_time, "%Y-%m-%dT%H:%M:%S.%f")

def time_parse(str_time):
  ctime = datetime.strptime(str_time, "%Y-%m-%dT%H:%M:%S.%f")
  td = ctime - starting_time
  return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 1000000.0) / 1000000.0

def mean_stddev(values):
  n = len(values)
  if n == 0:
    return (0, 0)

  sum_x = 0
  sum_x2 = 0

  for value in values:
    sum_x += value
    sum_x2 += (value * value)

  mean = sum_x / n
  stddev = math.sqrt((sum_x2 / n) - (mean * mean))
  return (mean, stddev)

class round:
  def __init__(self, round_id, start_time):
    self.round_id = round_id
    self.shuffle_time = 0
    self.phase = 0
    self.phase_start = 0
    self.total_time = 0
    self.average_time = 0
    self.stddev = 0
    self.phase_times = []
    self.completed_cleanly = False
    self.start_time = time_parse(start_time)

    self.clients = []
    self.total = 0

    self.client_ciphertexts = []
    self.client_avg = 0
    self.client_std = 0

  def finished(self, end_time):
    self.total_time = time_parse(end_time) - self.start_time
    self.average_time, self.stddev = mean_stddev(self.phase_times)
    self.clients_avg, self.client_std = mean_stddev(self.client_ciphertexts)

  def shuffle_finished(self, end_time):
    self.shuffle_time = time_parse(end_time) - self.start_time

  def next_phase(self, start_time):
    ctime = time_parse(start_time)
    if self.phase != 0:
      self.phase_times.append(ctime - self.phase_start)
    self.phase_start = ctime
    self.phase += 1

  def set_members(self, count, total):
    self.clients.append(count)

    if self.total != 0:
      assert(total == self.total)
    else:
      self.total = total

  def add_client_ciphertext(self, ctime):
    if self.phase != 0:
      self.client_ciphertexts.append(time_parse(ctime) - self.phase_start)

  def __str__(self):
    clients_avg, clients_std = mean_stddev(self.clients)
    online = []
    for client in self.clients:
      assert(client <= self.total)
      online.append((1.0 * client) / (1.0 * self.total))
    online_avg, online_stddev = mean_stddev(online)

    return "Round: %s, total phases: %i, total time: %.4f, " \
        "shuffle time: %.4f, average phase time: %.4f +/- %.4f, " \
        "online clients: %.4f +/- %.4f, total clients: %i, " \
        "percent online: %.4f +/- %.4f, client submit time: %.4f +/- %.4f" \
        % (self.round_id, self.phase, self.total_time, self.shuffle_time, \
        self.average_time, self.stddev, clients_avg, clients_std, self.total, \
        online_avg, online_stddev, self.clients_avg, self.client_std)

rounds = []
cround = None
line = sys.stdin.readline()

while line:
  if line.find("Debug") == -1:
    line = sys.stdin.readline()
    continue
  starting_time = time_parse0(line.split(" ")[0])
  break

while line:
  if line.find("starting round") != -1:
    ls = line.split(" ")
    cround = round(ls[7], ls[0])
    rounds.append(cround)
    cphase = 0
  elif line.find("finished due to") != -1:
    ls = line.split(" ")
    cround.finished(ls[0])
    cround = None
  elif line.find("ending phase") != -1:
    ls = line.split(" ")
    assert (cround.round_id == ls[6]) , "Wrong round"
    assert (cround.phase == int(ls[8][:-1])) , "Wrong phase: %s %s" % \
        (cround.phase, ls[8][:-1])
    cround.next_phase(ls[0])
  elif line.find("PREPARE_FOR_BULK") != -1:
    ls = line.split(" ")
    cround.shuffle_finished(ls[0])
  elif line.find("Phase: 0\" starting phase") != -1:
    ls = line.split(" ")
    cround.shuffle_finished(ls[0])
  elif line.find("generating ciphertext") != -1:
    ls = line.split(" ")
    count = int(ls[11])
    total = int(ls[14])
    cround.set_members(count, total)
  elif line.find("received client ciphertext") != -1:
    ls = line.split(" ")
    cround.add_client_ciphertext(ls[0])

  line = sys.stdin.readline()

if cround:
  cround.finished(ls[0])

shuffles = []
phases = []
clients = []

for rnd in rounds:
  print rnd
  if rnd.round_id in rounds_to_ignore:
    continue

  phases.extend(rnd.phase_times)
  shuffles.append(rnd.shuffle_time)
  clients.extend(rnd.clients)

print "Phase times: %.4f +/- %.4f" % (mean_stddev(phases))
print "Shuffle times: %.4f +/- %.4f" % (mean_stddev(shuffles))
print "Clients involved: %.4f +/- %.4f" % (mean_stddev(clients))

if output_base:
  output = open(output_base + ".client_times", "w+")
  for rnd in rounds:
    for stime in rnd.client_ciphertexts:
      output.write("%f\n" % (stime,))
  output.close()
