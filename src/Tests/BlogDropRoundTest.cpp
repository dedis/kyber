#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {

  class BlogDropRoundTest : 
    public ::testing::TestWithParam<bool> {
  };

  TEST_P(BlogDropRoundTest, BasicManaged)
  {
    RoundTest_Basic(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST_P(BlogDropRoundTest, MultiRoundManaged)
  {
    RoundTest_MultiRound(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST_P(BlogDropRoundTest, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST_P(BlogDropRoundTest, PeerDisconnectMiddleManaged)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST_P(BlogDropRoundTest, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  INSTANTIATE_TEST_CASE_P(BlogDropRound, BlogDropRoundTest,
      ::testing::Values(true, false));
}
}
