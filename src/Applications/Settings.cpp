#include "Utils/Logging.hpp"

#include "Settings.hpp"

using Dissent::Utils::Logging;

namespace Dissent {
namespace Applications {
  Settings::Settings(const QString &file, bool actions) :
    LocalId(Id::Zero()),
    LeaderId(Id::Zero()),
    SubgroupPolicy(Group::CompleteGroup),
    SuperPeer(false),
    _use_file(true),
    _settings(file, QSettings::IniFormat),
    _reason()
  {
    Init();
    QVariant peers = _settings.value(Param<Params::RemotePeers>());
    ParseUrlList("RemotePeer", peers, RemotePeers);

    QVariant endpoints = _settings.value(Param<Params::LocalEndPoints>());
    ParseUrlList("EndPoint", endpoints, LocalEndPoints);

    DemoMode = _settings.value(Param<Params::DemoMode>()).toBool();

    if(_settings.contains(Param<Params::LocalNodeCount>())) {
      LocalNodeCount = _settings.value(Param<Params::LocalNodeCount>()).toInt();
    }

    Console = _settings.value(Param<Params::Console>()).toBool();
    WebServer = _settings.value(Param<Params::WebServer>()).toBool();
    EntryTunnel = _settings.value(Param<Params::EntryTunnel>()).toBool();
    ExitTunnel = _settings.value(Param<Params::ExitTunnel>()).toBool();
    Multithreading = _settings.value(Param<Params::Multithreading>()).toBool();

    WebServerUrl = TryParseUrl(_settings.value(Param<Params::WebServerUrl>()).toString(), "http");
    EntryTunnelUrl = TryParseUrl(_settings.value(Param<Params::EntryTunnelUrl>()).toString(), "tcp");

    if(_settings.contains(Param<Params::SessionType>())) {
      SessionType = _settings.value(Param<Params::SessionType>()).toString();
    }

    if(_settings.contains(Param<Params::SubgroupPolicy>())) {
      QString ptype = _settings.value(Param<Params::SubgroupPolicy>()).toString();
      SubgroupPolicy = Group::StringToPolicyType(ptype);
    }

    if(_settings.contains(Param<Params::Log>())) {
      Log = _settings.value(Param<Params::Log>()).toString();
      QString lower = Log.toLower();

      if(actions) {
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
    }

    if(_settings.contains(Param<Params::LocalId>())) {
      LocalId = Id(_settings.value(Param<Params::LocalId>()).toString());
    }

    if(_settings.contains(Param<Params::LeaderId>())) {
      LeaderId = Id(_settings.value(Param<Params::LeaderId>()).toString());
    }

    if(_settings.contains(Param<Params::SuperPeer>())) {
      SuperPeer = _settings.value(Param<Params::SuperPeer>()).toBool();
    }
  }

  Settings::Settings() :
    Console(false),
    WebServer(false),
    EntryTunnel(false),
    ExitTunnel(false),
    LocalId(Id::Zero()),
    LeaderId(Id::Zero()),
    SubgroupPolicy(Group::CompleteGroup),
    _use_file(false)
  {
    Init();
  }

  void Settings::Init()
  {
    LocalNodeCount = 1;
    SessionType = "null";
    Console = false;
    WebServer = false;
  }

  bool Settings::IsValid()
  {
    if(_use_file && (_settings.status() != QSettings::NoError)) {
      _reason = "File error";
      return false;
    }

    if(LocalEndPoints.count() == 0) {
      _reason = "No locally defined end points";
      return false;
    }

    if(WebServer && (!WebServerUrl.isValid() || WebServerUrl.isEmpty())) {
      _reason = "Invalid WebServerUrl";
      return false;
    }

    if(EntryTunnel && (!EntryTunnelUrl.isValid() || EntryTunnelUrl.isEmpty())) {
      _reason = "Invalid WebServerUrl";
      return false;
    }

    if(LeaderId == Id::Zero()) {
      _reason = "No leader Id";
      return false;
    }

    if(SubgroupPolicy == -1) {
      _reason = "Invalid subgroup policy";
      return false;
    }

    return true;
  }

  QString Settings::GetError()
  {
    IsValid();
    return _reason;
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

  QUrl Settings::TryParseUrl(const QString &string_rep, const QString &scheme)
  {
    QUrl url = QUrl(string_rep);
    if(url.toString() != string_rep) {
      return QUrl();
    }

    if(url.scheme() != scheme) {
      return QUrl();
    }
    return url;
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
      _settings.setValue(Param<Params::RemotePeers>(), peers);
    }

    QStringList endpoints;
    foreach(QUrl endpoint, LocalEndPoints) {
      endpoints << endpoint.toString();
    }

    if(!endpoints.empty()) {
      _settings.setValue(Param<Params::LocalEndPoints>(), endpoints);
    }

    _settings.setValue(Param<Params::LocalNodeCount>(), LocalNodeCount);
    _settings.setValue(Param<Params::WebServer>(), WebServer);
    _settings.setValue(Param<Params::WebServerUrl>(), WebServerUrl);
    _settings.setValue(Param<Params::Console>(), Console);
    _settings.setValue(Param<Params::DemoMode>(), DemoMode);
    _settings.setValue(Param<Params::Log>(), Log);
    _settings.setValue(Param<Params::Multithreading>(), Multithreading);
    _settings.setValue(Param<Params::LocalId>(), LocalId.ToString());
    _settings.setValue(Param<Params::LeaderId>(), LeaderId.ToString());
    _settings.setValue(Param<Params::SubgroupPolicy>(),
        Group::PolicyTypeToString(SubgroupPolicy));
  }
}
}
