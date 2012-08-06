#include "Utils/Logging.hpp"

#include "AuthFactory.hpp"
#include "Settings.hpp"

using Dissent::Utils::Logging;

namespace Dissent {
namespace Applications {
  Settings::Settings(const QString &file, bool actions) :
    _use_file(true),
    _settings(new QSettings(file, QSettings::IniFormat))
  {
    Init(actions);
  }

  Settings::Settings() :
    _use_file(false),
    _settings(new QSettings())
  {
    Init();
  }

  Settings::Settings(const QSharedPointer<QSettings> &settings,
      bool file, bool actions) :
    _use_file(file),
    _settings(settings)
  {
    Init(actions);
  }

  void Settings::Init(bool actions)
  {
    if(_settings->value(Param<Params::Help>(), false).toBool()) {
      Help = true;
      return;
    }
    Help = false;

    LeaderId = Id::Zero();
    LocalNodeCount = 1;

    QVariant peers = _settings->value(Param<Params::RemotePeers>());
    ParseUrlList("RemotePeer", peers, RemotePeers);

    QVariant endpoints = _settings->value(Param<Params::LocalEndPoints>());
    ParseUrlList("EndPoint", endpoints, LocalEndPoints);

    QString auth_mode = _settings->value(Param<Params::AuthMode>(), "null").toString();
    AuthMode = AuthFactory::GetAuthType(auth_mode);

    if(_settings->contains(Param<Params::LocalNodeCount>())) {
      LocalNodeCount = _settings->value(Param<Params::LocalNodeCount>()).toInt();
    }

    Console = _settings->value(Param<Params::Console>(), false).toBool();
    ExitTunnel = _settings->value(Param<Params::ExitTunnel>(), false).toBool();
    Multithreading = _settings->value(Param<Params::Multithreading>(), false).toBool();

    WebServerUrl = TryParseUrl(_settings->value(Param<Params::WebServerUrl>()).toString(), "http");
    WebServer = WebServerUrl != QUrl();

    EntryTunnelUrl = TryParseUrl(_settings->value(Param<Params::EntryTunnelUrl>()).toString(), "tcp");
    EntryTunnel = EntryTunnelUrl != QUrl();

    ExitTunnelProxyUrl = TryParseUrl(_settings->value(Param<Params::ExitTunnelProxyUrl>()).toString(), "tcp");
    ExitTunnel = (ExitTunnelProxyUrl != QUrl()) || ExitTunnel;

    if(_settings->contains(Param<Params::SessionType>())) {
      QString stype = _settings->value(Param<Params::SessionType>()).toString();
      SessionType = SessionFactory::GetSessionType(stype);
    } else {
      SessionType = SessionFactory::NULL_ROUND;
    }

    if(_settings->contains(Param<Params::SubgroupPolicy>())) {
      QString ptype = _settings->value(Param<Params::SubgroupPolicy>()).toString();
      SubgroupPolicy = Group::StringToPolicyType(ptype);
    } else {
      SubgroupPolicy = Group::CompleteGroup;
    }

    if(_settings->contains(Param<Params::Log>())) {
      Log = _settings->value(Param<Params::Log>()).toString().toLower();
    }

    if(actions) {
      if(Log == "stderr") {
        Logging::UseStderr();
      } else if(Log == "stdout") {
        Logging::UseStdout();
      } else if(Log.isEmpty()) {
        Logging::Disable();
      } else {
        Logging::UseFile(Log);
      }
    }

    if(_settings->contains(Param<Params::LocalId>())) {
      QVariantList ids = _settings->value(Param<Params::LocalId>()).toList();
      foreach(const QVariant &id, ids) {
        LocalIds.append(Id(id.toString()));
      }
    }

    if(_settings->contains(Param<Params::LeaderId>())) {
      LeaderId = Id(_settings->value(Param<Params::LeaderId>()).toString());
    }

    SuperPeer = _settings->value(Param<Params::SuperPeer>(), false).toBool();


    PublicKeys = _settings->value(Param<Params::PublicKeys>()).toString();

    if(_settings->contains(Param<Params::PrivateKey>())) {
      QVariantList keys = _settings->value(Param<Params::PrivateKey>()).toList();
      foreach(const QVariant &key, keys) {
        PrivateKey.append(key.toString());
      }
    }
  }

  bool Settings::IsValid()
  {
    if(_use_file && (_settings->status() != QSettings::NoError)) {
      _reason = "File error";
      return false;
    }

    if(LocalEndPoints.count() == 0) {
      _reason = "No locally defined end points";
      return false;
    }

    if(WebServer && (!WebServerUrl.isValid() || WebServerUrl.isEmpty())) {
      _reason = "Invalid WebServerUrl: " + WebServerUrl.toString();
      return false;
    }

    if(EntryTunnel && (!EntryTunnelUrl.isValid() || EntryTunnelUrl.isEmpty())) {
      _reason = "Invalid EntryTunnelUrl: " + EntryTunnelUrl.toString();
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

    if(AuthMode == AuthFactory::INVALID) {
      _reason = "Invalid auth_mode";
      return false;
    } else if(AuthFactory::RequiresKeys(AuthMode)) {
      if(PublicKeys.isEmpty()) {
        _reason = "Missing path to public keys";
        return false;
      } else if(PrivateKey.size() != LocalNodeCount) {
        _reason = "Missing path to private key or sufficient private keys";
        return false;
      }
    }

    if(SessionType == SessionFactory::INVALID) {
      _reason = "Invalid session type";
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
      _settings->setValue(Param<Params::RemotePeers>(), peers);
    }

    QStringList endpoints;
    foreach(QUrl endpoint, LocalEndPoints) {
      endpoints << endpoint.toString();
    }

    if(!endpoints.empty()) {
      _settings->setValue(Param<Params::LocalEndPoints>(), endpoints);
    }

    _settings->setValue(Param<Params::LocalNodeCount>(), LocalNodeCount);
    _settings->setValue(Param<Params::WebServerUrl>(), WebServerUrl);
    _settings->setValue(Param<Params::Console>(), Console);
    _settings->setValue(Param<Params::AuthMode>(), AuthMode);
    _settings->setValue(Param<Params::Log>(), Log);
    _settings->setValue(Param<Params::Multithreading>(), Multithreading);
    QVariantList local_ids;
    foreach(const Id &id, LocalIds) {
      local_ids.append(id.ToString());
    }
    _settings->setValue(Param<Params::LocalId>(), local_ids);
    _settings->setValue(Param<Params::LeaderId>(), LeaderId.ToString());
    _settings->setValue(Param<Params::SubgroupPolicy>(),
        Group::PolicyTypeToString(SubgroupPolicy));
  }

  Settings Settings::CommandLineParse(const QStringList &params, bool actions)
  {
    QSharedPointer<QxtCommandOptions> options = GetOptions();
    options->parse(params);
    QSharedPointer<QSettings> settings;
    bool file = (options->positional().count() > 0);

    if(file) {
      settings = QSharedPointer<QSettings>(
          new QSettings(options->positional()[0], QSettings::IniFormat));
    } else {
      settings = QSharedPointer<QSettings>(new QSettings());
      // Bug in other platforms?? I do not know...
      settings->clear();
      if(params.size() == 1) {
        settings->setValue(Param<Params::Help>(), true);
      }
    }

    QMultiHash<QString, QVariant> kv_params = options->parameters();

    if(kv_params.value(Param<Params::Help>(), false).toBool() && file) {
      file = false;
      settings = QSharedPointer<QSettings>(new QSettings());
    }

    foreach(const QString &key, kv_params.uniqueKeys()) {
      if(options->value(key).type() == QVariant::String &&
          options->value(key).toString().isEmpty())
      {
        settings->setValue(key, true);
      } else {
        settings->setValue(key, options->value(key));
      }
    }

    return Settings(settings, file, actions);
  }

  QSharedPointer<QxtCommandOptions> Settings::GetOptions()
  {
    QSharedPointer<QxtCommandOptions> options(new QxtCommandOptions());

    options->add(Param<Params::Help>(),
        "help (this screen)",
        QxtCommandOptions::NoValue);

    options->add(Param<Params::RemotePeers>(),
        "list of remote peers",
        QxtCommandOptions::ValueRequired | QxtCommandOptions::AllowMultiple);

    options->add(Param<Params::LocalEndPoints>(),
        "list of local end points",
        QxtCommandOptions::ValueRequired | QxtCommandOptions::AllowMultiple);

    options->add(Param<Params::LocalNodeCount>(),
        "number of virtual nodes to start",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::AuthMode>(),
        "the type of authentication",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::SessionType>(),
        "the type of session",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::Log>(),
        "logging mechanism: stderr, stdout, or a file path",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::Console>(),
        "enable console",
        QxtCommandOptions::NoValue);

    options->add(Param<Params::WebServerUrl>(),
        "web server url (enables web server)",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::EntryTunnelUrl>(),
        "entry tunnel url (enables entry tunnel)",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::ExitTunnel>(),
        "enables exit tunnel",
        QxtCommandOptions::NoValue);

    options->add(Param<Params::ExitTunnelProxyUrl>(),
        "enables redirecting to a proxy at the end of an exit tunnel",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::Multithreading>(),
        "enables multithreading",
        QxtCommandOptions::NoValue);

    options->add(Param<Params::LocalId>(),
        "160-bit base64 local id",
        QxtCommandOptions::ValueRequired | QxtCommandOptions::AllowMultiple);

    options->add(Param<Params::LeaderId>(),
        "160-bit base64 leader id",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::SubgroupPolicy>(),
        "subgroup policy (defining servers)",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::SuperPeer>(),
        "sets this peer as a capable super peer",
        QxtCommandOptions::NoValue);

    options->add(Param<Params::PrivateKey>(),
        "a path to a private key",
        QxtCommandOptions::ValueRequired | QxtCommandOptions::AllowMultiple);

    options->add(Param<Params::PublicKeys>(),
        "a path to a directory containing public keys (public keys end in \".pub\"",
        QxtCommandOptions::ValueRequired);

    return options;
  }
}
}
