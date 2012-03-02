#ifndef DISSENT_APPLICATIONS_SETTINGS_H_GUARD
#define DISSENT_APPLICATIONS_SETTINGS_H_GUARD

#include <QtCore>
#include <QDebug>
#include <QHostAddress>
#include <QSettings>

#include "Connections/Id.hpp"
#include "Identity/Group.hpp"

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
       * The amount of nodes required before constructing an anonymity session
       */
      int GroupSize;

      /**
       * Amount of nodes to create locally
       */
      int LocalNodeCount;

      /**
       * Enable demo mode for evaluation / demo purposes
       */
      bool DemoMode;

      /**
       * The type of anonymity session / round to construct
       */
      QString SessionType;

      /**
       * Logging type: stderr, stdout, file, or empty (disabled)
       */
      QString Log;

      /**
       * Run an console interface?
       */
      bool Console;

      /**
       * Run an HTTP server?
       */
      bool WebServer;
      
      /**
       * IP:Port on which the HTTP server should listen
       */
      QUrl WebServerUrl;

      /**
       * Enable multhreaded operations
       */
      bool Multithreading;

      /**
       * The id for the (first) local node, other nodes will be random
       */
      Id LocalId;

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

    private:
      void Init();
      void ParseUrlList(const QString &name, const QVariant &values, QList<QUrl> &list);
      void ParseUrl(const QString &name, const QVariant &value, QList<QUrl> &list);

      bool _use_file;
      QSettings _settings;
      QString _reason;
  };
}
}

#endif
