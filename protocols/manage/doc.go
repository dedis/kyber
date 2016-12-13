/*
Package manage implements protocols used when setting up and testing
a tree.

The count-protocol returns the number of nodes in the tree that are reachable.
It also sets up all necessary connections, so if you want to do time-measurements
without including the setup-time, you can ran a count-protocol first.

The broadcast-protocol connects every node of the tree to every other node and
waits for all connections to be set up.

The close_all-protocol sends a 'terminate'-message to all nodes which will
close down everything.
*/
package manage
