#include <iostream>

#include <QDir>
#include <QTextStream>
#include <QxtCommandOptions>

#include "Dissent.hpp"

const char *CL_HELP = "help";
const char *CL_NKEYS = "nkeys";
const char *CL_LIB = "lib";
const char *CL_KEYTYPE = "key";
const char *CL_PUBDIR = "pubdir";
const char *CL_PRIVDIR = "privdir";
const char *CL_DEBUG = "debug";
const char *CL_RAND = "seed";

const char *DEFAULT_PUBDIR = "keys/public";
const char *DEFAULT_PRIVDIR = "keys/private";


void ExitWithWarning(const QxtCommandOptions &options, const char* warning)
{
  std::cerr << "Error: " << warning << std::endl;
  options.showUsage();
  exit(-1);
}

class CreateKey {
  public:
    virtual ~CreateKey() {}

    virtual AsymmetricKey *operator()()
    {
      return CryptoFactory::GetInstance().GetLibrary().CreatePrivateKey();
    }
};

class CreateSeededDsaKey : public CreateKey {
  public:
    explicit CreateSeededDsaKey(const QString &seed) :
      _dsa_key(CppDsaPrivateKey::GenerateKey(seed.toUtf8()))
    {
    }

    virtual AsymmetricKey *operator()()
    {
      return new CppDsaPrivateKey(_dsa_key->GetModulus(),
          _dsa_key->GetSubgroup(), _dsa_key->GetGenerator());
    }

  private:
    QSharedPointer<CppDsaPrivateKey> _dsa_key;
};

int main(int argc, char **argv)
{
  QxtCommandOptions options;

  options.add(CL_HELP, "display this help message",
      QxtCommandOptions::NoValue);
  options.add(CL_NKEYS, "number of keys to generate",
      QxtCommandOptions::ValueRequired);
  options.add(CL_PUBDIR, "directory in which to put public keys (default=./keys/pub)",
      QxtCommandOptions::ValueRequired);
  options.add(CL_PRIVDIR, "directory in which to put private keys (default=./keys/priv)",
      QxtCommandOptions::ValueRequired);
  options.add(CL_KEYTYPE, "specify the key type (default=dsa, options=dsa|rsa)",
      QxtCommandOptions::ValueRequired);
  options.add(CL_LIB, "specify the library (default=cryptopp, options=cryptopp)",
      QxtCommandOptions::ValueRequired);
  options.add(CL_RAND, "specify the base properties for the key (default=NULL)",
      QxtCommandOptions::ValueRequired);
  options.add(CL_DEBUG, "enable debugging",
      QxtCommandOptions::NoValue);

  options.parse(argc, argv);

  if(options.count(CL_HELP) || options.showUnrecognizedWarning()) {
    options.showUsage();
    return -1;
  }

  QMultiHash<QString, QVariant> params = options.parameters();

  int key_count = params.value(CL_NKEYS, 1).toInt();
  if(key_count < 1) {
    ExitWithWarning(options, "Invalid nkeys");
  }

  QString pubdir_path = params.value(CL_PUBDIR, DEFAULT_PUBDIR).toString();
  QDir pubdir(pubdir_path);
  if(!pubdir.exists()) {
    pubdir.mkpath(".");
  }

  if(!pubdir.exists()) {
    ExitWithWarning(options, "Unable to create pubdir");
  }

  QString privdir_path = params.value(CL_PRIVDIR, DEFAULT_PRIVDIR).toString();
  QDir privdir(privdir_path);
  if(!privdir.exists()) {
    privdir.mkpath(".");
  }

  if(!privdir.exists()) {
    ExitWithWarning(options, "Unable to create privdir");
  }

  if(params.contains(CL_DEBUG)) {
    Logging::UseStderr();
  }

  QString lib_name = params.value(CL_LIB, "cryptopp").toString();
  QString key = params.value(CL_KEYTYPE, "dsa").toString();

  CryptoFactory &cf = CryptoFactory::GetInstance();
  QSharedPointer<CreateKey> ck(new CreateKey());
  if(lib_name == "cryptopp") {
    if(key == "dsa") {
      cf.SetLibrary(CryptoFactory::CryptoPPDsa);
      if(params.contains(CL_RAND)) {
        ck = QSharedPointer<CreateKey>(
            new CreateSeededDsaKey(params.value(CL_RAND).toString()));
      }
    } else if (key == "rsa") {
      cf.SetLibrary(CryptoFactory::CryptoPP);
    } else {
      ExitWithWarning(options, "Invalid key type");
    }
  } else {
    ExitWithWarning(options, "Invalid library");
  }

  Library &lib = cf.GetLibrary();
  QSharedPointer<Hash> hash(lib.GetHashAlgorithm());

  int count = 0;
  while(count < key_count) {
    QSharedPointer<AsymmetricKey> key((*ck)());
    QSharedPointer<AsymmetricKey> pubkey(key->GetPublicKey());
    QByteArray hvalue = hash->ComputeHash(pubkey->GetByteArray());
    QString id = Integer(hvalue).ToString();

    if(!key->Save(privdir_path + QDir::separator() + id)) {
      qFatal("Could not save private key");
    }

    if(!pubkey->Save(pubdir_path + QDir::separator() + id + ".pub")) {
      qFatal("Could not save private key");
    }

    count++;
  }

  return 0;
}

