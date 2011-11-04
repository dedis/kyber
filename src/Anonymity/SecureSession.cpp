#include "SecureSession.hpp"

namespace Dissent {
namespace Anonymity {
  SecureSession::SecureSession(const Group &group, const Id &local_id,
      const Id &leader_id, const Id &session_id, ConnectionTable &ct,
      RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
      CreateSecureRound create_round, const QByteArray &default_data,
      CreateGroupGenerator group_generator) :
    Session(group, local_id, leader_id, session_id, ct, rpc, 0, default_data),
    _signing_key(signing_key),
    _create_secure_round(create_round),
    _generate_group(group_generator(group, session_id, ct, rpc, signing_key))
  {
  }

  Round *SecureSession::GetRound(const QByteArray &data)
  {
    const Group subgroup = _generate_group->NextGroup();
    return _create_secure_round(_group, subgroup, _local_id, _session_id,
        Id::Zero, _ct, _rpc, _signing_key, data);
  }
}
}
