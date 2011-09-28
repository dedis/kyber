#include "Settings.hpp"

namespace Dissent {
namespace Utils {
  Settings::Settings(const QString &file) :
    _use_file(true), _settings(file, QSettings::IniFormat)
  {
    QVariant peers = _settings.value("remote_peers");
    ParseUrlList("RemotePeer", peers, RemotePeers);

    QVariant endpoints = _settings.value("endpoints");
    ParseUrlList("EndPoint", endpoints, LocalEndPoints);
  }

  Settings::Settings() : _use_file(false)
  {
  }

  void Settings::ParseUrlList(const QString &name, const QVariant &values,
          QList<QUrl> &list)
  {
    if(values.isNull()) {
      return;
    }

    QVariantList varlist = values.toList();
    if(!varlist.empty()) {
      foreach(QVariant value, varlist) {
        ParseUrl(name, value, list);
      }
    } else {
      ParseUrl(name, values, list);
    }
  }

  inline void Settings::ParseUrl(const QString &name, const QVariant &value,
          QList<QUrl> &list)
  {
    QUrl url(value.toString());
    if(url.isValid()) {
      list << url;
    } else {
      qWarning() << "Invalid " << name << ": " << value.toString();
    }
  }

  void Settings::Save()
  {
    if(!_use_file) {
      return;
    }

    QStringList peers;
    foreach(QUrl peer, RemotePeers) {
      peers << peer.toString();
    }

    if(!peers.empty()) {
      _settings.setValue("remote_peers", peers);
    }

    QStringList endpoints;
    foreach(QUrl endpoint, LocalEndPoints) {
      endpoints << endpoint.toString();
    }

    if(!endpoints.empty()) {
      _settings.setValue("endpoints", endpoints);
    }
  }
}
}
