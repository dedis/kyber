#!/usr/bin/python
import math
import sys
import time

rounds_to_ignore = { }

def time_parse(str_time):
  return time.mktime(time.strptime(str_time, "%Y-%m-%dT%H:%M:%SZ"))

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
    self.phases = 0
    self.total_time = 0
    self.average_time = 0
    self.stddev = 0
    self.phase_times = []
    self.completed_cleanly = False
    self.start_time = time_parse(start_time)
    self.clients = []
    self.total = 0

  def finished(self, end_time):
    self.total_time = time_parse(end_time) - self.start_time
    self.average_time, self.stddev = mean_stddev(self.phase_times)

  def shuffle_finished(self, end_time):
    self.shuffle_time = time_parse(end_time) - self.start_time

  def phase_finished(self, start_time, end_time):
    self.phases += 1
    self.phase_times.append(time_parse(end_time) - time_parse(start_time))

  def set_members(self, count, total):
    self.clients.append(count)

    if self.total != 0:
      assert(total == self.total)
    else:
      self.total = total

  def __str__(self):
    clients_avg, clients_std = mean_stddev(self.clients)
    online = []
    for client in self.clients:
      assert(client <= self.total)
      online.append((1.0 * client) / (1.0 * self.total))
    online_avg, online_stddev = mean_stddev(online)

    return "Round: %s, total phases: %i, total time: %.4f, shuffle time: %.4f " \
        "average phase time: %.4f +/- %.4f, online clients: %.4f +/- %.4f, total " \
        "clients: %i, percent online: %.4f +/- %.4f"  % (self.round_id, \
        self.phases, self.total_time, self.shuffle_time, self.average_time, \
        self.stddev, clients_avg, clients_std, self.total, online_avg, \
        online_stddev)


rounds = []
cround = None
line = sys.stdin.readline()
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
    if cphase == int(ls[8][:-1]):
      assert (cphase == int(ls[8][:-1])) , "Wrong phase: %s %s" % (cphase, ls[8][:-1])
      if cphase != 0:
        cround.phase_finished(cphase_start, ls[0])
      cphase +=1
      cphase_start = ls[0]
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
