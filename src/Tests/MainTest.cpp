#include <time.h>

#include "DissentTest.hpp"

void FileExists(QString filename);
void FileDelete(QString filename);
void FilesExist();
void FilesDelete();

GTEST_API_ int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  Logging::Disable();
//  Logging::UseFile("test.log");
  qDebug() << "Begging tests";
  FilesExist();
  testing::InitGoogleTest(&argc, argv);
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
    qFatal("%s", QString(filename + " exists, move / delete and restart the test.").toUtf8().data());
  }
}

void FileDelete(QString filename)
{
  QFile file(filename);
  file.remove();
}
