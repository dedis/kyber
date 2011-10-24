#include "SecureSession.hpp"

namespace Dissent {
namespace Anonymity {
  SecureSession::SecureSession(const Group &group, const Id &local_id,
      const Id &leader_id, const Id &session_id, ConnectionTable &ct,
      RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
      CreateSecureRound create_round, const QByteArray &default_data) :
    Session(group, local_id, leader_id, session_id, ct, rpc, 0, default_data),
    _signing_key(signing_key),
    _create_secure_round(create_round)
  {
  }

  Round *SecureSession::GetRound(const QByteArray &data)
  {
    return _create_secure_round(_group, _local_id, _session_id, Id::Zero,
        _ct, _rpc, _signing_key, data);
  }
}
}
