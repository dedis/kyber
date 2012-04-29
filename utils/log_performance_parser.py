#!/usr/bin/python
from datetime import datetime
import getopt
import math
import sys

optlist, args = getopt.getopt(sys.argv[1:], "", ["output="])

optdict = {}

for k,v in optlist:
  optdict[k] = v

output_base = None
if "--output" in optdict:
  output_base = optdict["--output"]

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

  var = (sum_x2 / n) - (mean * mean)
  if var > 0:
    stddev = math.sqrt(var)
  else:
    stddev = 0

  return (mean, stddev)

class round:
  def __init__(self, round_id, start_time):
    self.round_id = round_id
    self.shuffle_time = 0
    self.cphase = 0
    self.phase = 0
    self.phase_start = 0
    self.total_time = 0
    self.average_time = 0
    self.stddev = 0
    self.phase_times = []
    self.completed_cleanly = False
    self.start_time = time_parse(start_time)

    self.clients = []
    self.online_clients = 0
    self.online_clients_std = 0
    self.total = 0

    self.client_ciphertexts = []
    self.client_avg = 0
    self.client_std = 0

  def finished(self, end_time):
    self.total_time = time_parse(end_time) - self.start_time

  def adding_data_set(self):
    self.cphase = 0

  def calculate_data(self):
    self.average_time, self.stddev = mean_stddev(self.phase_times)
    self.client_avg, self.client_std = mean_stddev(self.client_ciphertexts)
    self.online_clients, self.online_clients_std = mean_stddev(self.clients)

  def shuffle_finished(self, end_time):
    self.shuffle_time = time_parse(end_time) - self.start_time

  def set_phase_start(self, start_time):
    ctime = time_parse(start_time)
    self.phase_start = ctime
    self.cphase += 1

  def next_phase(self, start_time):
    ctime = time_parse(start_time)
    if self.phase != 0:
      self.phase_times.append(ctime - self.phase_start)
    self.phase_start = ctime
    self.phase += 1
    self.cphase = self.phase

  def set_members(self, count, total):
    self.clients.append(count)

    if self.total != 0:
      assert(total == self.total)
    else:
      self.total = total

  def add_client_ciphertext(self, ctime):
    if self.cphase != 0:
      self.client_ciphertexts.append(time_parse(ctime) - self.phase_start)

  def __str__(self):
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
        self.average_time, self.stddev, self.online_clients, \
        self.online_clients_std, self.total, online_avg, online_stddev, \
        self.client_avg, self.client_std)

cfile = file(args[0])
line = cfile.readline()

while line:
  if line.find("Debug") == -1:
    line = cfile.readline()
    continue
  starting_time = time_parse0(line.split(" ")[0])
  break

cfile.close()

update = False
rounds_by_id = {}
rounds = []
cround = None
line_num = 1
update = False

def start_round(ls):
  global cround, update
  if ls[7] in rounds_by_id:
    if not update:
      global lines
      lines = update_lines
      if cround:
        cround.finished(ls[0])
    update = True
    cround = rounds_by_id[ls[7]]
    cround.adding_data_set()
  else:
    cround = round(ls[7], ls[0])
    rounds_by_id[cround.round_id] = cround
    rounds.append(cround)

def finished_round(ls):
  global cround
  if cround != None:
    cround.finished(ls[0])
  cround = None

def set_phase_start(ls):
  cround.set_phase_start(ls[0])

def phase_finished(ls):
  assert (cround.round_id == ls[6]) , "Wrong round"
  assert (cround.phase == int(ls[8][:-1])) , "Wrong phase: %s %s" % \
      (cround.phase, ls[8][:-1])
  cround.next_phase(ls[0])

def shuffle_finished(ls):
  cround.shuffle_finished(ls[0])

def client_count(ls):
  count = int(ls[11])
  total = int(ls[14])
  cround.set_members(count, total)

def client_data(ls):
  cround.add_client_ciphertext(ls[0])

default_lines = {
    "starting round" : start_round, \
    "finished due to" : finished_round, \
    "ending phase" : phase_finished, \
    "PREPARE_FOR_BULK" : shuffle_finished, \
    "Phase: 0\" starting phase": shuffle_finished, \
    "generating ciphertext" : client_count, \
    "received client ciphertext" : client_data \
    }

update_lines = {
    "starting round" : start_round, \
    "received client ciphertext" : client_data, \
    "ending phase" : set_phase_start \
    }

lines = default_lines

for fname in args:
  cfile = file(fname)
  line = cfile.readline()

  while line:
    for key in lines.keys():
      if line.find(key) != -1:
        lines[key](line.split())

    line_num += 1
    line = cfile.readline()

if not update and cround:
  cround.finished(ls[0])

shuffles = []
phases = []
clients = []

for rnd in rounds:
  rnd.calculate_data()
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

  output = open(output_base + ".online_clients", "w+")
  for rnd in rounds:
    for clients in rnd.clients:
      output.write("%d\n" % (clients,))
  output.close()

  
  output = open(output_base + ".csv", "w+")
  output.write("Round, total phases, total time, shuffle time, average " \
      "phase time,, online clients,, total clients, client submit time\n")
  for rnd in rounds:
    output.write("%s, %i, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %i, %.4f, " \
        "%.4f\n" % (rnd.round_id, rnd.phase, rnd.total_time, \
        rnd.shuffle_time, rnd.average_time, rnd.stddev, rnd.online_clients, \
        rnd.online_clients_std, rnd.total, rnd.client_avg, rnd.client_std))
  output.close()
