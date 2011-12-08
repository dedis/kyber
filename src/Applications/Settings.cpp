#include "../Utils/Logging.hpp"

#include "Settings.hpp"

using Dissent::Utils::Logging;

namespace Dissent {
namespace Applications {
  Settings::Settings(const QString &file) :
    GroupSize(40),
    LocalNodeCount(1),
    SessionType("null"),
    Console(false),
    WebServer(false),
    WebServerPort(8080),
    WebServerHost(QHostAddress::Any),
    _use_file(true),
    _settings(file, QSettings::IniFormat),
    _reason()
  {
    QVariant peers = _settings.value("remote_peers");
    ParseUrlList("RemotePeer", peers, RemotePeers);

    QVariant endpoints = _settings.value("endpoints");
    ParseUrlList("EndPoint", endpoints, LocalEndPoints);

    DemoMode = _settings.value("demo_mode").toBool();

    if(_settings.contains("group_size")) {
      GroupSize = _settings.value("group_size").toInt();
    }

    if(_settings.contains("local_nodes")) {
      LocalNodeCount = _settings.value("local_nodes").toInt();
    }

    if(_settings.contains("web_server_port")) {
      WebServerPort = _settings.value("web_server_port").toInt();
    }

    if(_settings.contains("web_server_host")) {
      QString hoststr = _settings.value("web_server_host").toString();

      if(hoststr == "*") {
        WebServerHost = QHostAddress::Any;
      } else {
        WebServerHost.setAddress(hoststr);
      }
    }

    if(_settings.contains("session_type")) {
      SessionType = _settings.value("session_type").toString();
    }

    if(_settings.contains("log")) {
      Log = _settings.value("log").toString();
      QString lower = Log.toLower();
      if(lower == "stderr") {
        Logging::UseStderr();
      } else if(lower == "stdout") {
        Logging::UseStdout();
      } else if(Log.isEmpty()) {
        Logging::Disable();
      } else {
        Logging::UseFile(Log);
      }
    }

    Console = _settings.value("console").toBool();
    WebServer = _settings.value("web_server").toBool();
    Multithreading = _settings.value("multithreading").toBool();
    LocalId = _settings.value("local_id").toString();
  }

  bool Settings::IsValid()
  {
    if(_settings.status() != QSettings::NoError) {
      _reason = "File error";
      return false;
    }

    if(LocalEndPoints.count() == 0) {
      _reason = "No locally defined end points";
      return false;
    }

    if((WebServerPort <= 0) || (WebServerPort > ((1 << 16) - 1))) {
      _reason = "Invalid port number"; 
      return false;
    }

    if(WebServerHost.isNull()) {
      _reason = "Invalid web host address";
      return false;
    }

    return true;
  }

  QString Settings::GetError()
  {
    IsValid();
    return _reason;
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
      qCritical() << "Invalid " << name << ": " << value.toString();
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

    _settings.setValue("group_size", GroupSize);
    _settings.setValue("local_nodes", LocalNodeCount);
    _settings.setValue("web_server_port", WebServerPort);
    _settings.setValue("web_server", WebServer);
    _settings.setValue("console", Console);
    _settings.setValue("demo_mode", DemoMode);
    _settings.setValue("log", Log);
    _settings.setValue("multithreading", Multithreading);
    _settings.setValue("local_id", LocalId);
  }
}
}
