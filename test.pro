include(dissent.pro)
TEMPLATE = app
TARGET = test
DEPENDPATH += ext/googletest/src \
              ext/googletest/include/gtest \
              ext/googletest/include/gtest/internal
INCLUDEPATH += src \
               ext/googletest \
               ext/googletest/include
#DEFINES += QT_NO_DEBUG_OUTPUT
#DEFINES += QT_NO_WARNING_OUTPUT

# Input
HEADERS += ext/googletest/include/gtest/gtest-death-test.h \
           ext/googletest/include/gtest/gtest-message.h \
           ext/googletest/include/gtest/gtest-param-test.h \
           ext/googletest/include/gtest/gtest-printers.h \
           ext/googletest/include/gtest/gtest-spi.h \
           ext/googletest/include/gtest/gtest-test-part.h \
           ext/googletest/include/gtest/gtest-typed-test.h \
           ext/googletest/include/gtest/gtest.h \
           ext/googletest/include/gtest/gtest_pred_impl.h \
           ext/googletest/include/gtest/gtest_prod.h \
           ext/googletest/include/gtest/internal/gtest-death-test-internal.h \
           ext/googletest/include/gtest/internal/gtest-filepath.h \
           ext/googletest/include/gtest/internal/gtest-internal.h \
           ext/googletest/include/gtest/internal/gtest-linked_ptr.h \
           ext/googletest/include/gtest/internal/gtest-param-util-generated.h \
           ext/googletest/include/gtest/internal/gtest-param-util.h \
           ext/googletest/include/gtest/internal/gtest-port.h \
           ext/googletest/include/gtest/internal/gtest-string.h \
           ext/googletest/include/gtest/internal/gtest-tuple.h \
           ext/googletest/include/gtest/internal/gtest-type-util.h \
           src/Tests/DissentTest.hpp \
           src/Tests/Mock.hpp \
           src/Tests/RpcTest.hpp \
           src/Tests/TestNode.hpp \
           src/Tests/RoundTest.hpp \
           src/Tests/ShuffleRoundHelpers.hpp \
           src/Tests/BulkRoundHelpers.hpp \
           src/Tests/RepeatingBulkRoundHelpers.hpp \
           src/Tests/TrustedBulkRoundHelpers.hpp

SOURCES += ext/googletest/src/gtest-all.cc \
           src/Tests/AddressTest.cpp \
           src/Tests/MainTest.cpp \
           src/Tests/Mock.cpp \
           src/Tests/TimeTest.cpp \
           src/Tests/RpcTest.cpp \
           src/Tests/EdgeTest.cpp \
           src/Tests/IdTest.cpp \
           src/Tests/ConnectionTest.cpp \
           src/Tests/SettingsTest.cpp \
           src/Tests/GroupTest.cpp \
           src/Tests/NullRoundTest.cpp \
           src/Tests/Crypto.cpp \
           src/Tests/OnionTest.cpp \
           src/Tests/RandomTest.cpp \
           src/Tests/HashTest.cpp \
           src/Tests/RoundTest.cpp \
           src/Tests/TestNode.cpp \
           src/Tests/LogTest.cpp \
           src/Tests/ShuffleRoundTest.cpp \
           src/Tests/BasicGossipTest.cpp \
           src/Tests/TcpTest.cpp \
           src/Tests/IntegerTest.cpp \
           src/Tests/TripleTest.cpp \
           src/Tests/SerializationTest.cpp \
           src/Tests/BulkRoundTest.cpp \
           src/Tests/RepeatingBulkRoundTest.cpp \
           src/Tests/TrustedBulkRoundTest.cpp \
           src/Tests/PackagersTest.cpp
