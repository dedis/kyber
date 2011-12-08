#ifndef DISSENT_APPLICATIONS_SETTINGS_H_GUARD
#define DISSENT_APPLICATIONS_SETTINGS_H_GUARD

#include <QtCore>
#include <QDebug>
#include <QHostAddress>
#include <QSettings>

namespace Dissent {
namespace Applications {
  /**
   * Abstracts interaction with a configuration file
   */
  class Settings {
    public:
      /**
       * Load configuration from disk
       */
      Settings(const QString &file);

      /**
       * Create configuration in memory
       */
      Settings();

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
       * Port on which the HTTP server should listen
       */
      int WebServerPort;

      /**
       * Hostname on which the HTTP server should listen
       */ 
      QHostAddress WebServerHost;

      /**
       * Enable multhreaded operations
       */
      bool Multithreading;

      /**
       * The id for the (first) local node, other nodes will be random
       */
      QString LocalId;

    private:
      void ParseUrlList(const QString &name, const QVariant &values, QList<QUrl> &list);
      void ParseUrl(const QString &name, const QVariant &value, QList<QUrl> &list);

      bool _use_file;
      QSettings _settings;
      QString _reason;
  };
}
}

#endif
