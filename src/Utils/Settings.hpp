#include <QtCore>
#include <QDebug>
#include <QSettings>

#ifndef DISSENT_UTILS_SETTINGS_H_GUARD
#define DISSENT_UTILS_SETTINGS_H_GUARD

namespace Dissent {
namespace Utils {
  class Settings {
    public:
      Settings(const QString &file);
      Settings();
      void Save();
      QList<QUrl> RemotePeers;
      QList<QUrl> LocalEndPoints;
    private:
      void ParseUrlList(const QString &name, const QVariant &values, QList<QUrl> &list);
      void ParseUrl(const QString &name, const QVariant &value, QList<QUrl> &list);

      bool _use_file;
      QSettings _settings;
  };
}
}

#endif
