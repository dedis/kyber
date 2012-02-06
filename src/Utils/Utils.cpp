#include <QDebug>
#include <QIODevice>
#include <QTextStream>

#include "Utils.hpp"

#ifdef __linux__
#include <sys/time.h>
#include <sys/resource.h>
#endif

namespace Dissent {
namespace Utils {
  void PrintResourceUsage(const QString &label)
  {
    QTextStream qtout(stdout, QIODevice::WriteOnly);
#ifdef __linux__
    struct rusage usage;
    if(getrusage(RUSAGE_SELF, &usage)) {
      qtout << "!BENCHMARK!" << label << "| Unable to get resource usage";
      return;
    }
    QString user_sec = QString::number(usage.ru_utime.tv_sec);
    QString user_usec = QString::number(usage.ru_utime.tv_usec);
    QString sys_sec = QString::number(usage.ru_stime.tv_sec);
    QString sys_usec = QString::number(usage.ru_stime.tv_usec);

    QString user = QString("%1.%2").arg(user_sec).arg(user_usec, 6, '0');
    QString sys = QString("%1.%2").arg(sys_sec).arg(sys_usec, 6, '0');

    qtout << "!BENCHMARK!" << label << "| user:" << user << "| system:" << sys;
#else
    qtout << "!BENCHMARK!" << label << "| Unable to get resource usage";
#endif
  }
}
}
