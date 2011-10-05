#ifndef DISSENT_TEST_H_GUARD
#define DISSENT_TEST_H_GUARD

#include <qapplication.h>
#include <stdio.h>
#include <stdlib.h>

#include <gtest/gtest.h>

#include "Dissent.hpp"
#include "Mock.hpp"
#include "RpcTest.hpp"

void NoOutputHandler(QtMsgType, const char *);
void DisableLogging();
void EnableLogging();
int random(int min = 0, int max = RAND_MAX);

#endif
