/*
Package onet is the Overlay Network which offers a simple framework for generating
your own distributed systems. It is based on a description of your protocol
and offers sending and receiving messages, handling trees and host-lists, and
easy deploying to Localhost, Deterlab or a real-system.

ONet is based on the following pieces:

- Local* - offers the user-interface to the API for deploying your protocol
locally and for testing
- Node / ProtocolInstance - gives an interface to define your protocol
- Server - hold states for the different parts of Onet
- network - uses secured connections between hosts

If you just want to use an existing protocol, usually the ONet-part is enough.
If you want to create your own protocol, you have to learn how to use the
ProtocolInstance.
*/
package onet

// Version of onet.
const Version = "1"
