#include <QDebug>
#include "Utils.hpp"

#ifdef __linux__
#include <sys/time.h>
#include <sys/resource.h>
#endif

namespace Dissent {
namespace Utils {
  bool MultiThreading = true;
  bool Testing = false;

  void PrintResourceUsage(const QString &label)
  {
#ifdef QT_DEBUG
#ifdef __linux__
    struct rusage usage;
    if(getrusage(RUSAGE_SELF, &usage)) {
      qDebug() << "!BENCHMARK!" << label << "| Unable to get resource usage";
      return;
    }
    QString user_sec = QString::number(usage.ru_utime.tv_sec);
    QString user_usec = QString::number(usage.ru_utime.tv_usec);
    QString sys_sec = QString::number(usage.ru_stime.tv_sec);
    QString sys_usec = QString::number(usage.ru_stime.tv_usec);

    QString user = QString("%1.%2").arg(user_sec).arg(user_usec, 6, '0');
    QString sys = QString("%1.%2").arg(sys_sec).arg(sys_usec, 6, '0');

    qDebug() << "!BENCHMARK!" << label << "| user:" << user << "| system:" << sys;
#else
    qDebug() << "!BENCHMARK!" << label << "| Unable to get resource usage";
#endif
#endif
  }
 
  QByteArray ToUrlSafeBase64(const QByteArray &data)
  {
    /*
     * The following is borrowed from Qt using LGPL 2.1 / GPL 3.0
     */
    const char alphabet[] = "ABCDEFGH" "IJKLMNOP" "QRSTUVWX" "YZabcdef"
                "ghijklmn" "opqrstuv" "wxyz0123" "456789-_";
    const char padchar = '=';
    int padlen = 0;
    
    QByteArray tmp((data.size() * 4) / 3 + 3, Qt::Uninitialized);
  
    int i = 0;
    char *out = tmp.data();
    const char *in = data.constData();
    while (i < data.size()) {
      int chunk = 0;
      chunk |= int(uchar(in[i++])) << 16;
      if (i == data.size()) {
        padlen = 2;
      } else {
        chunk |= int(uchar(in[i++])) << 8;
        if (i == data.size()) {
          padlen = 1;
        } else {
          chunk |= int(uchar(in[i++]));
        }
      }

      int j = (chunk & 0x00fc0000) >> 18;
      int k = (chunk & 0x0003f000) >> 12;
      int l = (chunk & 0x00000fc0) >> 6;
      int m = (chunk & 0x0000003f);
      *out++ = alphabet[j];
      *out++ = alphabet[k];

      if (padlen > 1) {
        *out++ = padchar;
      } else {
        *out++ = alphabet[l];
      }
      if (padlen > 0) {
        *out++ = padchar;
      } else {
        *out++ = alphabet[m];
      }
    }
    
    tmp.truncate(out - tmp.data());
    return tmp;
  }

  QByteArray FromUrlSafeBase64(const QByteArray &base64)
  {
    /*
     * The following is borrowed from Qt using LGPL 2.1 / GPL 3.0
     */
    unsigned int buf = 0;
    int nbits = 0;
    QByteArray tmp((base64.size() * 3) / 4, Qt::Uninitialized);

    int offset = 0;
    for (int i = 0; i < base64.size(); ++i) {
      int ch = base64.at(i);
      int d;

      if (ch >= 'A' && ch <= 'Z') {
        d = ch - 'A';
      } else if (ch >= 'a' && ch <= 'z') {
        d = ch - 'a' + 26;
      } else if (ch >= '0' && ch <= '9') {
        d = ch - '0' + 52;
      } else if (ch == '-') {
        d = 62;
      } else if (ch == '_') {
        d = 63;
      } else {
        d = -1;
      }

      if (d != -1) {
        buf = (buf << 6) | d;
        nbits += 6;
        if (nbits >= 8) {
          nbits -= 8;
          tmp[offset++] = buf >> nbits;
          buf &= (1 << nbits) - 1;
        }
      }
    }

    tmp.truncate(offset);
    return tmp;
  }
}
}
