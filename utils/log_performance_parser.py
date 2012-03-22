#!/usr/bin/python
import math
import sys
import time

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
    self.phases = 0
    self.total_time = 0
    self.average_time = 0
    self.stddev = 0
    self.phase_times = []
    self.completed_cleanly = False
    self.start_time = time_parse(start_time)

  def finished(self, end_time):
    self.total_time = time_parse(end_time) - self.start_time
    self.average_time, self.stddev = mean_stddev(self.phase_times)

  def phase_finished(self, start_time, end_time):
    self.phases += 1
    self.phase_times.append(time_parse(end_time) - time_parse(start_time))

  def __str__(self):
    return "Round: %s, total phases: %i, total time: %f, average phase " \
        "time: %f, phase std dev: %f" % (self.round_id, self.phases, \
        self.total_time, self.average_time, self.stddev)

rounds = []
line = sys.stdin.readline()
while line:
  if line.find("starting round") != -1:
    ls = line.split(" ")
    cround = round(ls[7], ls[0])
    rounds.append(cround)
  elif line.find("finished due to") != -1:
    ls = line.split(" ")
    cround.finished(ls[0])
  elif line.find("starting phase") != -1:
    ls = line.split(" ")
    assert (cround.round_id == ls[6]) , "Wrong round"
    cphase = ls[8][:-1]
    cphase_start = ls[0]
  elif line.find("ending phase") != -1:
    ls = line.split(" ")
    assert (cround.round_id == ls[6]) , "Wrong round"
    assert (cphase == ls[8][:-1]) , "Wrong phase"
    cround.phase_finished(cphase_start, ls[0])
  line = sys.stdin.readline()

for rnd in rounds:
  print rnd
