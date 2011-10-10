#include <time.h>

#include <QtGlobal>

#include "DissentTest.hpp"

void FileExists(QString filename);
void FileDelete(QString filename);
void FilesExist();
void FilesDelete();

GTEST_API_ int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  FilesExist();
  qsrand(time(NULL));
  testing::InitGoogleTest(&argc, argv);
  Dissent::Init();
  int res = RUN_ALL_TESTS();
  FilesDelete();
  return res;
}

void FilesExist()
{
  FileExists("dissent.ini");
  FileExists("private_key");
  FileExists("public_key");
}

void FilesDelete()
{
  FileDelete("dissent.ini");
  FileDelete("private_key");
  FileDelete("public_key");
}

void FileExists(QString filename)
{
  QFile file(filename);
  if(file.exists()) {
    qFatal(QString(filename + " exists, move / delete and restart the test.").toUtf8().data());
  }
}

void FileDelete(QString filename)
{
  QFile file(filename);
  file.remove();
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
