#include <time.h>

#include <QtGlobal>

#include "DissentTest.hpp"

GTEST_API_ int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  QFile file("dissent.ini");
  if(file.exists()) {
    qFatal("dissent.ini exists, move / delete and restart the test.");
  }
  qsrand(time(NULL));
  testing::InitGoogleTest(&argc, argv);
  Dissent::Init();
  int res = RUN_ALL_TESTS();
  file.remove();
  return res;
}

void NoOutputHandler(QtMsgType, const char *)
{
}

void DisableLogging()
{
    qInstallMsgHandler(NoOutputHandler);
} 

void EnableLogging()
{
    qInstallMsgHandler(0);
}

int random(int min, int max)
{
  if(max <= min) {
    return min;
  }

  int value = qrand() % max;
  while(value <= min) {
    value = qrand() % max;
  }
  return value;
}
