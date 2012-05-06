#!/usr/bin/python
from datetime import datetime
import getopt
import math
import os
import sys

optlist, args = getopt.getopt(sys.argv[1:], "", ["path=", "output=", "lost_delay=", "min_clients="])

optdict = {}

for k,v in optlist:
  optdict[k] = v

path = "."
if "--path" in optdict:
  path = optdict["--path"]

output_base = None
if "--output" in optdict:
  output_base = optdict["--output"]

plot_lost = False
if "--lost_delay" in optdict:
  lost_delay = int(optdict["--lost_delay"])
  plot_lost = True

min_clients = 0
if "--min_clients" in optdict:
  min_clients = int(optdict["--min_clients"])

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
    self.start_user_time = 0
    self.start_sys_time = 0
    self.start_time = time_parse(start_time)
    self.cpu_times = []
    self.client_window = {}

    self.clients = []
    self.online_clients = 0
    self.online_clients_std = 0
    self.total = 0

    self.ignored_clients = 0
    self.expected_clients = 0
    self.submitted_clients = 0
    self.client_ciphertexts = []
    self.slowest_client_ciphertexts = {}
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
    self.expected_clients = 0
    ctime = time_parse(start_time)
    self.phase_start = ctime
    self.cphase += 1
    if self.cphase not in self.slowest_client_ciphertexts:
      self.slowest_client_ciphertexts[self.cphase] = 0

  def next_phase(self, start_time):
    ctime = time_parse(start_time)

    if self.phase != 0:
      self.phase_times.append(ctime - self.phase_start)
      if self.expected_clients != self.submitted_clients:
        if plot_lost:
          self.add_client_ciphertext_parsed(lost_delay)
        else:
          self.ignored_clients += (self.expected_clients - self.submitted_clients)

    self.submitted_clients = 0
    self.phase_start = ctime
    self.phase += 1
    self.cphase = self.phase
    self.slowest_client_ciphertexts[self.cphase] = 0

  def set_members(self, count, total):
    self.clients.append(count)

    if self.total != 0:
      assert(total == self.total)
    else:
      self.total = total

  def add_client_ciphertext(self, ctime):
    if self.cphase != 0:
      dtime = time_parse(ctime) - self.phase_start
      self.add_client_ciphertext_parsed(dtime)

  def add_client_ciphertext_parsed(self,dtime):
#      if self.add_client_ciphertext_95_plus_1_10(dtime):
      if True:
        self.submitted_clients += 1
        self.client_ciphertexts.append(dtime)
        self.slowest_client_ciphertexts[self.cphase] = max(self.slowest_client_ciphertexts[self.cphase], dtime)
      else:
        self.ignored_clients += 1

  def set_expected_client(self, expected_clients):
    self.expected_clients = expected_clients
    self.expected_clients_95 = int(self.expected_clients * .95)
    self.current_clients = 0
    self.clients_95_time_1_10 = 0

  def add_client_ciphertext_95_plus_1_10(self, dtime):
    if self.expected_clients_95 <= self.current_clients:
      if self.expected_clients_95 == self.current_clients:
        self.clients_95_time_1_10 = dtime * 1.1
      elif self.clients_95_time_1_10 < dtime:
        return False
    self.current_clients += 1
    return True

  def client_state_finished(self, ctime):
    if self.cphase == 0:
      return
    dtime = time_parse(ctime) - self.phase_start
    current = 0
    if self.cphase in self.client_window:
      current = self.client_window[self.cphase]
    self.client_window[self.cphase] = max(current, dtime)

  def set_cpu_start_time(self, sys_time, user_time):
    self.start_sys_time = sys_time
    self.start_user_time = user_time

  def set_cpu_end_time(self, sys_time, user_time):
    if self.start_sys_time == 0:
      return
    self.cpu_times.append((sys_time - self.start_sys_time) +\
        (user_time - self.start_user_time))
    
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
  if cround.expected_clients == 0:
    cround.set_expected_client(int(ls[16]))
  cround.add_client_ciphertext(ls[0])

def client_state_finished(ls):
  cround.client_state_finished(ls[0])

def cpu_start(ls):
  cround.set_cpu_start_time(float(ls[13][1:-2]), float(ls[16][1:-2]))

def cpu_end(ls):
  if cround:
    cround.set_cpu_end_time(float(ls[13][1:-2]), float(ls[16][1:-2]))

default_lines = {
    "starting round" : start_round, \
    "finished due to" : finished_round, \
    "ending phase" : phase_finished, \
    "PREPARE_FOR_BULK" : shuffle_finished, \
    "Phase: 0\" starting phase": shuffle_finished, \
    "ending: \"SERVER_WAIT_FOR_CLIENT_CIPHERTEXT\"": client_state_finished, \
    "generating ciphertext" : client_count, \
    "received client ciphertext" : client_data, \
    "beginning bulk" : cpu_start, \
    "finished bulk" : cpu_end \
    }

update_lines = {
    "starting round" : start_round, \
    "received client ciphertext" : client_data, \
    "ending: \"SERVER_WAIT_FOR_CLIENT_CIPHERTEXT\"": client_state_finished, \
    "ending phase" : set_phase_start, \
    "beginning bulk" : cpu_start, \
    "finished bulk" : cpu_end \
    }

lines = default_lines

for fname in args:
  print "Parsing " + fname
  cfile = file(fname)
  line = cfile.readline()

  while line:
    for key in lines.keys():
      if line.find(key) != -1:
        ls = line.split()
        try:
          lines[key](ls)
        except:
          print "Exception on: " + line
          raise

    line_num += 1
    line = cfile.readline()

if not update and cround:
  cround.finished(ls[0])

shuffles = []
phases = []
clients = []
ignored = 0
clients_total = 0

if min_clients > 0:
  all_rounds = rounds
  rounds = []
  for rnd in all_rounds:
    if len(rnd.clients) == 0:
      continue
    elif rnd.clients[0] < min_clients:
      continue
    rounds.append(rnd)

for rnd in rounds:
  rnd.calculate_data()
  print rnd

  ignored += rnd.ignored_clients
  clients_total += len(rnd.client_ciphertexts)
  phases.extend(rnd.phase_times)
  shuffles.append(rnd.shuffle_time)
  clients.extend(rnd.clients)

print "Phase times: %.4f +/- %.4f" % (mean_stddev(phases))
print "Shuffle times: %.4f +/- %.4f" % (mean_stddev(shuffles))
print "Clients involved: %.4f +/- %.4f" % (mean_stddev(clients))
if ignored != 0:
  print "Ignored clients total: %d / %d, percentage: %f" % \
      (ignored, clients_total + ignored, (100.0 * ignored) / (1.0 * (clients_total + ignored)))


if output_base:
  for top_path in ("client_times", "online_clients", "slowest", \
      "client_window", "phases", "cpu_time", "ignored"):
    full_path = "%s/%s" % (path, top_path)
    if os.path.exists(full_path):
      continue
    os.makedirs(full_path)

  output = open("%s/%s/%s" % (path, "client_times", output_base), "w+")
  for rnd in rounds:
    for stime in rnd.client_ciphertexts:
      output.write("%f\n" % (stime,))
  output.close()

  output = open("%s/%s/%s" % (path, "online_clients", output_base), "w+")
  for rnd in rounds:
    for clients in rnd.clients:
      output.write("%d\n" % (clients,))
  output.close()

  output = open("%s/%s.csv" % (path, output_base), "w+")
  output.write("Round, total phases, total time, shuffle time, average " \
      "phase time,, online clients,, total clients, client submit time\n")
  for rnd in rounds:
    output.write("%s, %i, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %i, %.4f, " \
        "%.4f\n" % (rnd.round_id, rnd.phase, rnd.total_time, \
        rnd.shuffle_time, rnd.average_time, rnd.stddev, rnd.online_clients, \
        rnd.online_clients_std, rnd.total, rnd.client_avg, rnd.client_std))
  output.close()

  output = open("%s/%s/%s" % (path, "slowest", output_base), "w+")
  for rnd in rounds:
    for slowest in rnd.slowest_client_ciphertexts.values():
      output.write("%f\n" % (slowest,))
  output.close()

  output = open("%s/%s/%s" % (path, "phases", output_base), "w+")
  for phase in phases:
    output.write("%f\n" % (phase,))
  output.close()

  output = open("%s/%s/%s" % (path, "cpu_time", output_base), "w+")
  for rnd in rounds:
    phase_count = rnd.phase
    if phase_count <= 0:
      continue

    for cpu_time in rnd.cpu_times:
      if cpu_time < 0:
        continue
      output.write("%f\n" % (cpu_time / phase_count,))
  output.close()

  output = open("%s/%s/%s" % (path, "client_window", output_base), "w+")
  for rnd in rounds:
    for window in rnd.client_window.values():
      output.write("%f\n" % (window,))
  output.close()

  output = open("%s/%s/%s" % (path, "ignored", output_base), "w+")
  for rnd in rounds:
    if rnd.ignored_clients > 0:
      output.write("%f\n" % ((1.0 * rnd.ignored_clients) / (1.0 * len(rnd.client_ciphertexts) + rnd.ignored_clients),))
  output.close()
