#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {

  class BlogDropRoundTest : 
    public ::testing::TestWithParam<bool> {
  };

  TEST(BlogDropRoundTest, BasicManaged)
  {
    RoundTest_Basic(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, MultiRoundManaged)
  {
    RoundTest_MultiRound(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, AddOne)
  {
    RoundTest_AddOne(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, PeerDisconnectMiddleManaged)
  {
    RoundTest_PeerDisconnectMiddle(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound>),
        Group::ManagedSubgroup);
  }
}
}
