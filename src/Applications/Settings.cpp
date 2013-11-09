#include "Transports/AddressFactory.hpp"
#include "Utils/Logging.hpp"

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

    QVariant remote = _settings->value(Param<Params::RemoteEndPoints>());
    RemoteEndPoints = ParseAddressList("RemoteEndPoints", remote);

    QVariant local = _settings->value(Param<Params::LocalEndPoints>());
    LocalEndPoints = ParseAddressList("EndPoint", local);

    Auth = _settings->value(Param<Params::Auth>(), true).toBool();
    LocalNodeCount = _settings->value(Param<Params::LocalNodeCount>(), 1).toInt();
    Console = _settings->value(Param<Params::Console>(), false).toBool();
    ExitTunnel = _settings->value(Param<Params::ExitTunnel>(), false).toBool();
    Multithreading = _settings->value(Param<Params::Multithreading>(), false).toBool();

    WebServerUrl = TryParseUrl(_settings->value(Param<Params::WebServerUrl>()).toString(), "http");
    WebServer = WebServerUrl != QUrl();

    EntryTunnelUrl = TryParseUrl(_settings->value(Param<Params::EntryTunnelUrl>()).toString(), "tcp");
    EntryTunnel = EntryTunnelUrl != QUrl();

    ExitTunnelProxyUrl = TryParseUrl(_settings->value(Param<Params::ExitTunnelProxyUrl>()).toString(), "tcp");
    ExitTunnel = (ExitTunnelProxyUrl != QUrl()) || ExitTunnel;

    if(_settings->contains(Param<Params::RoundType>())) {
      QString stype = _settings->value(Param<Params::RoundType>()).toString();
      RoundType = Anonymity::RoundFactory::GetRoundType(stype);
    } else {
      RoundType = Anonymity::RoundFactory::NULL_ROUND;
    }

    Log = _settings->value(Param<Params::Log>(), "null").toString();

    QString log_lower = Log.toLower();
    if(actions) {
      if(log_lower == "stderr") {
        Logging::UseStderr();
      } else if(log_lower == "stdout") {
        Logging::UseStdout();
      } else if(log_lower == "null" || log_lower.isEmpty()) {
        Logging::Disable();
      } else {
        Logging::UseFile(Log);
      }
    }

    if(_settings->contains(Param<Params::LocalId>())) {
      LocalId = ParseIdList(_settings->value(Param<Params::LocalId>()));
    }

    if(_settings->contains(Param<Params::ServerIds>())) {
      ServerIds = ParseIdList(_settings->value(Param<Params::ServerIds>()));
    }

    PublicKeys = _settings->value(Param<Params::PublicKeys>()).toString();
    PrivateKeys = _settings->value(Param<Params::PrivateKeys>()).toString();
  }

  bool Settings::IsValid()
  {
    if(_use_file && (_settings->status() != QSettings::NoError)) {
      _reason = "File error";
      return false;
    }

    if(!LocalEndPoints.count()) {
      _reason = "No local end points";
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

    if(!ServerIds.count()) {
      _reason = "No server Ids";
      return false;
    }

    if(Auth && (LocalId.count() != LocalNodeCount)) {
      _reason = QString("Insufficient local ids, found %1, expected %2.").
        arg(LocalId.count()).arg(LocalNodeCount);
      return false;
    }

    if(RoundType == Anonymity::RoundFactory::INVALID) {
      _reason = "Invalid round type: " +
        _settings->value(Param<Params::RoundType>()).toString();
      return false;
    }

    return true;
  }

  QString Settings::GetError()
  {
    IsValid();
    return _reason;
  }

  QList<Transports::Address> Settings::ParseAddressList(const QString &name,
      const QVariant &values)
  {
    QList<Transports::Address> list;
    if(values.isNull()) {
      return list;
    }

    QVariantList varlist = values.toList();
    if(!varlist.empty()) {
      foreach(QVariant value, varlist) {
        list.append(Transports::AddressFactory::GetInstance().
            CreateAddress(ParseUrl(name, value)));
      }
    } else {
      list.append(Transports::AddressFactory::GetInstance().
          CreateAddress(ParseUrl(name, values)));
    }

    return list;
  }

  QUrl Settings::ParseUrl(const QString &name, const QVariant &value)
  {
    QUrl url(value.toString());
    if(!url.isValid()) {
      qFatal("Invalid %s: %s", name.toLatin1().data(),
          value.toString().toLatin1().data());
    }
    return url;
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

  QList<Connections::Id> Settings::ParseIdList(const QVariant &qids)
  {
    QList<Connections::Id> id_list;

    QVariantList ids = qids.toList();
    if(!ids.empty()) {
      foreach(const QVariant &id, ids) {
        id_list.append(Connections::Id(id.toString()));
      }
    } else {
      id_list.append(Connections::Id(qids.toString()));
    }

    return id_list;
  }

  void Settings::Save()
  {
    if(!_use_file) {
      return;
    }

    QStringList peers;
    foreach(const Transports::Address &addr, RemoteEndPoints) {
      peers << addr.ToString();
    }

    if(!peers.empty()) {
      _settings->setValue(Param<Params::RemoteEndPoints>(), peers);
    }

    QStringList endpoints;
    foreach(const Transports::Address &addr, LocalEndPoints) {
      endpoints << addr.ToString();
    }

    if(!endpoints.empty()) {
      _settings->setValue(Param<Params::LocalEndPoints>(), endpoints);
    }

    _settings->setValue(Param<Params::LocalNodeCount>(), LocalNodeCount);
    _settings->setValue(Param<Params::WebServerUrl>(), WebServerUrl);
    _settings->setValue(Param<Params::Console>(), Console);
    _settings->setValue(Param<Params::Auth>(), Auth);
    _settings->setValue(Param<Params::Log>(), Log);
    _settings->setValue(Param<Params::Multithreading>(), Multithreading);

    QVariantList local_ids;
    foreach(const Connections::Id &id, LocalId) {
      local_ids.append(id.ToString());
    }
    _settings->setValue(Param<Params::LocalId>(), local_ids);

    QVariantList server_ids;
    foreach(const Connections::Id &id, ServerIds) {
      server_ids.append(id.ToString());
    }
    _settings->setValue(Param<Params::ServerIds>(), server_ids);
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

    options->add(Param<Params::RemoteEndPoints>(),
        "list of remote end points",
        QxtCommandOptions::ValueRequired | QxtCommandOptions::AllowMultiple);

    options->add(Param<Params::LocalEndPoints>(),
        "list of local end points",
        QxtCommandOptions::ValueRequired | QxtCommandOptions::AllowMultiple);

    options->add(Param<Params::LocalNodeCount>(),
        "number of virtual nodes to start",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::Auth>(),
        "bool, enable or disable authentication",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::RoundType>(),
        "the type of round",
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
        "one or more 160-bit base64 local id",
        QxtCommandOptions::ValueRequired | QxtCommandOptions::AllowMultiple);

    options->add(Param<Params::ServerIds>(),
        "one or more 160-bit base64 server id",
        QxtCommandOptions::ValueRequired);

    options->add(Param<Params::PrivateKeys>(),
        "a path to a directory containing private keys",
        QxtCommandOptions::ValueRequired | QxtCommandOptions::AllowMultiple);

    options->add(Param<Params::PublicKeys>(),
        "a path to a directory containing public keys (public keys end in \".pub\"",
        QxtCommandOptions::ValueRequired);

    return options;
  }
}
}
