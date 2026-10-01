//go:build !linux

package server

import "net"

// loopbackPeerUID cannot look up the peer of a loopback TCP connection on
// this OS: the ingress listener accepts it and warns once (DESIGN §10.6: a
// local user gains nothing by forging a Funnel request, loopback is always
// allowed on the main port).
func loopbackPeerUID(net.Conn) (int, error) { return -1, errPeerUnverifiable }
