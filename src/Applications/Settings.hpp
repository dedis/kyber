#ifndef DISSENT_APPLICATIONS_SETTINGS_H_GUARD
#define DISSENT_APPLICATIONS_SETTINGS_H_GUARD

#include <QtCore>
#include <QDebug>
#include <QHostAddress>
#include <QSettings>
#include <QSharedPointer>
#include <QxtCommandOptions>

#include "Connections/Id.hpp"
#include "Transports/Address.hpp"
#include "Anonymity/RoundFactory.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Abstracts interaction with a configuration file
   */
  class Settings {
    public:
      /**
       * Load configuration from disk
       * @param file the file with the settings contained therein
       * @param actions whether or not the settings file should change system
       * configuration values or just be a container for configuration data,
       * the default (true) is the latter.
       */
      explicit Settings(const QString &file, bool actions = true);
      
      static Settings CommandLineParse(const QStringList &params,
          bool actions = true);

      static QString GetUsage()
      {
        static QSharedPointer<QxtCommandOptions> options = GetOptions();
        return options->getUsage();
      }

      /**
       * Create configuration in memory
       */
      explicit Settings();

      /**
       * Store the configuration data back to the file
       */
      void Save();

      /**
       * True if the configuration file represents a valid configuration
       */
      bool IsValid();

      /**
       * If the configuration file is invalid, returns the reason why
       */
      QString GetError();

      /**
       * List of bootstrap peers
       */
      QList<Transports::Address> RemoteEndPoints;
      
      /**
       * List of local urls to construct EdgeListeners from
       */
      QList<Transports::Address> LocalEndPoints;

      /**
       * Amount of nodes to create locally
       */
      int LocalNodeCount;

      /**
       * Enable demo mode for evaluation / demo purposes
       */
      bool Auth;

      /**
       * The type of anonymity round to construct
       */
      Anonymity::RoundFactory::RoundType RoundType;

      /**
       * Logging type: stderr, stdout, file, or empty (disabled)
       */
      QString Log;

      /**
       * Provide a Console UI
       */
      bool Console;

      /**
       * Provide a WebServer interface
       */
      bool WebServer;
      
      /**
       * IP:Port on which the HTTP server should listen
       */
      QUrl WebServerUrl;

      /**
       * Provide a IP Tunnel Entry point
       */
      bool EntryTunnel;

      /**
       * IP:Port on which the Tunnel Entry point will run
       */
      QUrl EntryTunnelUrl;

      /**
       * Provide a IP Tunnel Exit point
       */
      bool ExitTunnel;

      /**
       * In addition to enabling ExitTunnel, this also redirects all traffic
       * to a secondary Tunnel after leaving Dissent
       */
      QUrl ExitTunnelProxyUrl;

      /**
       * Enable multhreaded operations
       */
      bool Multithreading;

      /**
       * The id for local nodes
       */
      QList<Connections::Id> LocalId;

      /**
       * The Ids for the set of servers
       */
      QList<Connections::Id> ServerIds;

      /**
       * Path to a directory containing private keys
       */
      QString PrivateKeys;

      /**
       * Path to a directory containing public keys
       */
      QString PublicKeys;

      bool Help;

      static const char* CParam(int id)
      {
        static const char* params[] = {
          "help",
          "remote_endpoints",
          "local_endpoints",
          "local_nodes",
          "auth",
          "round_type",
          "log",
          "console",
          "web_server_url",
          "entry_tunnel_url",
          "exit_tunnel",
          "exit_tunnel_proxy_url",
          "multithreading",
          "local_id",
          "server_ids",
          "path_to_private_keys",
          "path_to_public_keys"
        };
        return params[id];
      }

      class Params {
        public:
          enum OptionId {
            Help = 0,
            RemoteEndPoints,
            LocalEndPoints,
            LocalNodeCount,
            Auth,
            RoundType,
            Log,
            Console,
            WebServerUrl,
            EntryTunnelUrl,
            ExitTunnel,
            ExitTunnelProxyUrl,
            Multithreading,
            LocalId,
            ServerIds,
            PrivateKeys,
            PublicKeys
          };
      };

      template<int OptionId> static QString Param()
      {
        static QString param(CParam(OptionId));
        return param;
      }

    private:
      static QSharedPointer<QxtCommandOptions> GetOptions();
      Settings(const QSharedPointer<QSettings> &settings, bool file, bool actions);
      void Init(bool actions = false);
      QList<Transports::Address> ParseAddressList(const QString &name, const QVariant &values);
      QUrl ParseUrl(const QString &name, const QVariant &value);
      QUrl TryParseUrl(const QString &string_rep, const QString &scheme);
      QList<Connections::Id> ParseIdList(const QVariant &qids);

      bool _use_file;
      QSharedPointer<QSettings> _settings;
      QString _reason;
  };
}
}

#endif
