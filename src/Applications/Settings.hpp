#ifndef DISSENT_APPLICATIONS_SETTINGS_H_GUARD
#define DISSENT_APPLICATIONS_SETTINGS_H_GUARD

#include <QtCore>
#include <QDebug>
#include <QHostAddress>
#include <QSettings>
#include <QSharedPointer>
#include <QxtCommandOptions>

#include "Connections/Id.hpp"
#include "Identity/Group.hpp"

#include "AuthFactory.hpp"
#include "SessionFactory.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Abstracts interaction with a configuration file
   */
  class Settings {
    public:
      typedef Connections::Id Id;
      typedef Identity::Group Group;

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
      QList<QUrl> RemotePeers;
      
      /**
       * List of local urls to construct EdgeListeners from
       */
      QList<QUrl> LocalEndPoints;

      /**
       * Amount of nodes to create locally
       */
      int LocalNodeCount;

      /**
       * Enable demo mode for evaluation / demo purposes
       */
      AuthFactory::AuthType AuthMode;

      /**
       * The type of anonymity session / round to construct
       */
      SessionFactory::SessionType SessionType;

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
       * The id for the (first) local node, other nodes will be random
       */
      QList<Id> LocalIds;

      /**
       * The id for the anonymity group's leader
       */
      Id LeaderId;

      /**
       * The subgroup policy employed at this node
       */
      Group::SubgroupPolicy SubgroupPolicy;

      /**
       * SuperPeer capable?
       */
      bool SuperPeer;

      /**
       * List of private keys mapped the LocalIds
       */
      QList<QString> PrivateKey;

      /**
       * Path to a directory containing public keys
       */
      QString PublicKeys;

      bool Help;

      static const char* CParam(int id)
      {
        static const char* params[] = {
          "help",
          "remote_peers",
          "endpoints",
          "local_nodes",
          "auth_mode",
          "session_type",
          "log",
          "console",
          "web_server_url",
          "entry_tunnel_url",
          "exit_tunnel",
          "exit_tunnel_proxy_url",
          "multithreading",
          "local_id",
          "leader_id",
          "subgroup_policy",
          "super_peer",
          "path_to_private_key",
          "path_to_public_keys"
        };
        return params[id];
      }

      class Params {
        public:
          enum OptionId {
            Help = 0,
            RemotePeers,
            LocalEndPoints,
            LocalNodeCount,
            AuthMode,
            SessionType,
            Log,
            Console,
            WebServerUrl,
            EntryTunnelUrl,
            ExitTunnel,
            ExitTunnelProxyUrl,
            Multithreading,
            LocalId,
            LeaderId,
            SubgroupPolicy,
            SuperPeer,
            PrivateKey,
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
      void ParseUrlList(const QString &name, const QVariant &values, QList<QUrl> &list);
      void ParseUrl(const QString &name, const QVariant &value, QList<QUrl> &list);
      QUrl TryParseUrl(const QString &string_rep, const QString &scheme);

      bool _use_file;
      QSharedPointer<QSettings> _settings;
      QString _reason;
  };
}
}

#endif
