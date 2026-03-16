package kobenet

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Network is one operator's view of the mesh: its own index + identity key, the
// pinned identity keys of every peer, and the live connections. It exposes a
// channel of authenticated inbound Envelopes (Inbox) that the protocol driver
// reads, and a Broadcast / SendTo pair the driver calls to route tss-lib output.
//
// The connection mesh is built once at Start: this operator dials every peer
// with a lower-or-... — actually i<j dials, i>j accepts — see Start. Every byte
// that crosses the wire is an Envelope whose Ed25519 signature is verified
// against the sender's pinned key before it reaches Inbox.
type Network struct {
	self    int
	moniker string
	priv    ed25519.PrivateKey
	peers   map[int]Peer // by index, excludes self
	session string

	mu    sync.Mutex
	conns map[int]*conn

	inbox  chan *Envelope
	errs   chan error
	closed chan struct{}
	once   sync.Once

	finished atomicBool // set once this operator's own party has produced its result
	finCh    chan int   // peer indices that have sent their FIN control frame

	// tlsm is the M8 mutual-TLS material. When non-nil, every peer connection is
	// wrapped in mutual TLS (RequireAndVerifyClientCert + per-operator pin)
	// before the application handshake runs. When nil, the legacy raw-socket +
	// Ed25519-handshake path is used (kept for the in-process unit tests).
	tlsm *tlsMaterial

	logf func(string, ...any)
}

// atomicBool is a tiny lock-free flag.
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set()      { b.mu.Lock(); b.v = true; b.mu.Unlock() }
func (b *atomicBool) get() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.v }

// NewNetwork builds an operator's network state. peers must include every OTHER
// operator (not self). session ties this run together (DKG and signing use
// distinct sessions so a frame from one can't be replayed into the other).
func NewNetwork(self int, moniker string, priv ed25519.PrivateKey, peers []Peer, session string, logf func(string, ...any)) *Network {
	pm := make(map[int]Peer, len(peers))
	for _, p := range peers {
		if p.Index == self {
			continue
		}
		pm[p.Index] = p
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Network{
		self:    self,
		moniker: moniker,
		priv:    priv,
		peers:   pm,
		session: session,
		conns:   make(map[int]*conn),
		inbox:   make(chan *Envelope, 256),
		errs:    make(chan error, 8),
		closed:  make(chan struct{}),
		finCh:   make(chan int, len(pm)+1),
		logf:    logf,
	}
}

// NewNetworkTLS builds an operator network that wraps every peer connection in
// mutual TLS (Milestone 8). identity is this operator's Ed25519 key (also the
// TLS leaf key); ownLeafDER / caDER are this operator's leaf cert and the
// operator-set CA cert; each peer in `peers` must carry its pinned CertDER.
func NewNetworkTLS(self int, moniker string, identity ed25519.PrivateKey, peers []Peer, session string, ownLeafDER, caDER []byte, logf func(string, ...any)) (*Network, error) {
	n := NewNetwork(self, moniker, identity, peers, session, logf)
	tlsm, err := buildTLSMaterial(self, identity, ownLeafDER, caDER, n.peerSlice())
	if err != nil {
		return nil, err
	}
	n.tlsm = tlsm
	return n, nil
}

// peerSlice returns the peer directory (excluding self) as a slice.
func (n *Network) peerSlice() []Peer {
	out := make([]Peer, 0, len(n.peers))
	for _, p := range n.peers {
		out = append(out, p)
	}
	return out
}

// Inbox is the stream of authenticated inbound messages for the protocol driver.
func (n *Network) Inbox() <-chan *Envelope { return n.inbox }

// Errs surfaces transport-level failures (a peer dropped, a frame failed auth,
// a malformed frame). The driver selects on this to abort cleanly.
func (n *Network) Errs() <-chan error { return n.errs }

func (n *Network) raise(err error) {
	select {
	case n.errs <- err:
	default:
	}
}

// Start brings up the mesh and blocks until every peer connection is
// established (or timeout). listenAddr is this operator's own host:port.
//
// Connection rule: for each peer pair, the LOWER index dials and the HIGHER
// index accepts, so each pair forms exactly one TCP connection. The dialer sends
// its index first; both sides run handshake() to prove identity-key ownership
// and pin the verified peer index to the connection.
func (n *Network) Start(listenAddr string, timeout time.Duration) error {
	rawLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	ln := rawLn.(*net.TCPListener)

	// Count how many peers will dial US (those with a lower index).
	expectAccept := 0
	for idx := range n.peers {
		if idx < n.self {
			expectAccept++
		}
	}

	var wg sync.WaitGroup
	var dialErr, acceptErr error
	var emu sync.Mutex

	// Accept loop for the lower-indexed peers dialing in.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < expectAccept; i++ {
			_ = ln.SetDeadline(time.Now().Add(timeout))
			nc, err := ln.Accept()
			if err != nil {
				emu.Lock()
				acceptErr = fmt.Errorf("accept: %w", err)
				emu.Unlock()
				return
			}
			nc, err = n.wrapServerTLS(nc)
			if err != nil {
				emu.Lock()
				acceptErr = err
				emu.Unlock()
				_ = nc.Close()
				return
			}
			peerIdx, err := n.handshake(nc, false)
			if err != nil {
				emu.Lock()
				acceptErr = err
				emu.Unlock()
				_ = nc.Close()
				return
			}
			n.register(peerIdx, nc)
		}
	}()

	// Dial the higher-indexed peers.
	for idx, p := range n.peers {
		if idx <= n.self {
			continue
		}
		wg.Add(1)
		go func(peerIdx int, addr string) {
			defer wg.Done()
			var nc net.Conn
			deadline := time.Now().Add(timeout)
			for {
				var err error
				nc, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					emu.Lock()
					dialErr = fmt.Errorf("dial peer %d at %s: %w", peerIdx, addr, err)
					emu.Unlock()
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			nc, err := n.wrapClientTLS(nc)
			if err != nil {
				emu.Lock()
				dialErr = fmt.Errorf("dial peer %d at %s: %w", peerIdx, addr, err)
				emu.Unlock()
				_ = nc.Close()
				return
			}
			got, err := n.handshake(nc, true)
			if err != nil {
				emu.Lock()
				dialErr = err
				emu.Unlock()
				_ = nc.Close()
				return
			}
			if got != peerIdx {
				emu.Lock()
				dialErr = fmt.Errorf("peer at %s claimed index %d, expected %d", addr, got, peerIdx)
				emu.Unlock()
				_ = nc.Close()
				return
			}
			n.register(peerIdx, nc)
		}(idx, p.Addr)
	}

	wg.Wait()
	_ = ln.Close()
	emu.Lock()
	defer emu.Unlock()
	if dialErr != nil {
		return dialErr
	}
	if acceptErr != nil {
		return acceptErr
	}
	return nil
}

// wrapServerTLS completes the TLS server handshake on an accepted connection
// when mutual TLS is configured; otherwise it returns the raw connection. The
// TLS handshake here is what verifies the dialer's client certificate against
// the operator-set CA and the per-operator pin (verifyPinned) BEFORE any
// application bytes flow.
func (n *Network) wrapServerTLS(nc net.Conn) (net.Conn, error) {
	if n.tlsm == nil {
		return nc, nil
	}
	tc := tls.Server(nc, n.tlsm.serverConfig())
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return nc, fmt.Errorf("tls server handshake: %w", err)
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

// wrapClientTLS completes the TLS client handshake on a dialed connection when
// mutual TLS is configured; otherwise it returns the raw connection.
func (n *Network) wrapClientTLS(nc net.Conn) (net.Conn, error) {
	if n.tlsm == nil {
		return nc, nil
	}
	tc := tls.Client(nc, n.tlsm.clientConfig())
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return nc, fmt.Errorf("tls client handshake: %w", err)
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

// tlsPeerIndex, for a TLS connection, returns the operator index the peer's
// (already TLS-verified, CA-chained, set-pinned) leaf certificate belongs to.
// This is the authenticated identity the application handshake binds the
// claimed index against. Returns -1 if the connection is not TLS or the leaf is
// somehow unpinned (which verifyPinned should already have rejected).
func (n *Network) tlsPeerIndex(nc net.Conn) int {
	tc, ok := nc.(*tls.Conn)
	if !ok || n.tlsm == nil {
		return -1
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return -1
	}
	return n.tlsm.peerIndexForSPKI(certs[0].RawSubjectPublicKeyInfo)
}

// handshake proves identity-key ownership on a fresh connection and returns the
// verified peer index. Protocol (symmetric challenge-response):
//
//	dialer sends:  hello{from, pubkey, nonce}
//	listener sends: hello{from, pubkey, nonce}
//	each side signs the OTHER side's nonce with its identity key and sends it;
//	each side verifies that signature against the peer's PINNED pubkey.
//
// The pubkey on the wire is checked against the static peer directory: a peer
// that presents a key we didn't pin, or fails to sign the challenge, is rejected
// before any protocol message flows. This is what stops a spoofed operator from
// joining the mesh.
func (n *Network) handshake(nc net.Conn, _ bool) (int, error) {
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	defer nc.SetDeadline(time.Time{})

	myNonce := make([]byte, 32)
	if _, err := io.ReadFull(randReader{}, myNonce); err != nil {
		return -1, err
	}

	// Send our hello.
	if err := writeHello(nc, n.self, n.priv.Public().(ed25519.PublicKey), myNonce); err != nil {
		return -1, fmt.Errorf("send hello: %w", err)
	}
	// Read peer hello.
	peerIdx, peerPub, peerNonce, err := readHello(nc)
	if err != nil {
		return -1, fmt.Errorf("read hello: %w", err)
	}
	// The claimed index must be a known peer, and the presented key must match
	// the one we pinned for that index.
	want, ok := n.peers[peerIdx]
	if !ok {
		return -1, fmt.Errorf("handshake: unknown peer index %d", peerIdx)
	}
	if !pubEqual(want.PubKey, peerPub) {
		return -1, fmt.Errorf("handshake: peer %d presented key %s, pinned %s (impersonation rejected)",
			peerIdx, hex.EncodeToString(peerPub)[:16], hex.EncodeToString(want.PubKey)[:16])
	}
	// Under mutual TLS, the peer already proved possession of a CA-issued,
	// set-pinned leaf certificate during the TLS handshake. Bind the index the
	// peer CLAIMS in-band to the index its TLS CERTIFICATE actually belongs to,
	// so a member operator cannot present a valid cert for index A while
	// claiming to be index B.
	if n.tlsm != nil {
		certIdx := n.tlsPeerIndex(nc)
		if certIdx != peerIdx {
			return -1, fmt.Errorf("handshake: peer claims index %d but its TLS certificate belongs to operator %d (cert/identity mismatch rejected)", peerIdx, certIdx)
		}
	}
	// Prove ownership: sign the peer's nonce, verify the peer's signature of ours.
	mySig := ed25519.Sign(n.priv, peerNonce)
	if _, err := nc.Write(frameBytes(mySig)); err != nil {
		return -1, fmt.Errorf("send proof: %w", err)
	}
	proof, err := readFrameBytes(nc)
	if err != nil {
		return -1, fmt.Errorf("read proof: %w", err)
	}
	if !ed25519.Verify(peerPub, myNonce, proof) {
		return -1, fmt.Errorf("handshake: peer %d failed challenge (not the identity-key holder)", peerIdx)
	}
	return peerIdx, nil
}

// register stores a verified connection and starts its read loop.
func (n *Network) register(peerIdx int, nc net.Conn) {
	c := &conn{peer: peerIdx, nc: nc}
	n.mu.Lock()
	n.conns[peerIdx] = c
	n.mu.Unlock()
	n.logf("transport: connected to operator %d (%s)", peerIdx, nc.RemoteAddr())
	go n.readLoop(c)
}

// readLoop reads frames off one peer connection, verifies each against the
// peer's pinned identity key, and forwards authenticated Envelopes to Inbox. A
// malformed frame, a frame failing auth, or a frame impersonating a different
// sender raises an error (the driver aborts) — it is never delivered.
func (n *Network) readLoop(c *conn) {
	peer := n.peers[c.peer]
	for {
		e, err := readFrame(c.nc)
		if err != nil {
			// A disconnect AFTER this operator has produced its own result is the
			// normal end of the run (the peer finished and tore down). Only a
			// disconnect or read error BEFORE we finish is a real abort — that is
			// the failure case the negative test exercises.
			if n.finished.get() {
				return
			}
			if err != io.EOF {
				n.raise(fmt.Errorf("operator %d: read from peer %d: %w", n.self, c.peer, err))
			} else {
				n.raise(fmt.Errorf("operator %d: peer %d disconnected", n.self, c.peer))
			}
			return
		}
		// The frame must claim to be from the peer that owns this connection, be
		// in this session, and carry a valid signature by that peer's pinned key.
		if e.From != c.peer {
			n.raise(fmt.Errorf("operator %d: peer %d sent a frame claiming sender %d (spoof rejected)", n.self, c.peer, e.From))
			return
		}
		if e.Session != n.session {
			n.raise(fmt.Errorf("operator %d: peer %d sent wrong session %q", n.self, c.peer, e.Session))
			return
		}
		if !e.Verify(peer.PubKey) {
			n.raise(fmt.Errorf("operator %d: peer %d frame failed identity-key verification (tampered/forged)", n.self, c.peer))
			return
		}
		if e.Fin {
			// Authenticated completion barrier: this peer has produced its result
			// and is draining. Record it; the read loop keeps running so any in
			// flight protocol frames already on the wire are still delivered.
			n.logf("wire ◄ FIN       op%d ← op%d  (peer finished)", n.self, e.From)
			select {
			case n.finCh <- e.From:
			default:
			}
			continue
		}
		kind := "P2P"
		if e.IsBroadcast {
			kind = "BROADCAST"
		}
		n.logf("wire ◄ %-9s op%d ← op%d  %d bytes (auth OK)", kind, n.self, e.From, len(e.Payload))
		select {
		case n.inbox <- e:
		case <-n.closed:
			return
		}
	}
}

// Broadcast signs and sends e to every connected peer (used for tss-lib
// broadcast messages, GetTo()==nil).
func (n *Network) Broadcast(payload []byte) error {
	e := &Envelope{Session: n.session, From: n.self, To: -1, IsBroadcast: true, Payload: payload}
	e.Sign(n.priv)
	n.mu.Lock()
	conns := make([]*conn, 0, len(n.conns))
	for _, c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		if err := c.send(e); err != nil {
			return fmt.Errorf("broadcast to peer %d: %w", c.peer, err)
		}
		n.logf("wire ► BROADCAST  op%d → op%d  %d bytes (signed)", n.self, c.peer, len(payload))
	}
	return nil
}

// SendTo signs and sends e to one peer (used for tss-lib point-to-point
// messages, GetTo() set).
func (n *Network) SendTo(to int, payload []byte) error {
	e := &Envelope{Session: n.session, From: n.self, To: to, IsBroadcast: false, Payload: payload}
	e.Sign(n.priv)
	n.mu.Lock()
	c := n.conns[to]
	n.mu.Unlock()
	if c == nil {
		return fmt.Errorf("no connection to peer %d", to)
	}
	n.logf("wire ► P2P        op%d → op%d  %d bytes (signed)", n.self, to, len(payload))
	return c.send(e)
}

// Fin runs the completion barrier once this operator's party has produced its
// result. It marks the operator finished (so a later peer disconnect is the
// normal end of the run, not an abort), broadcasts a signed FIN control frame to
// every peer, and blocks until it has received a FIN from every peer or the
// barrier times out. This guarantees no operator tears its sockets down while a
// peer still needs its final protocol broadcast — which is what otherwise causes
// the slower party to see a spurious "peer disconnected" mid-final-round.
func (n *Network) Fin(timeout time.Duration) {
	n.finished.set()
	fin := &Envelope{Session: n.session, From: n.self, To: -1, IsBroadcast: true, Fin: true}
	fin.Sign(n.priv)
	n.mu.Lock()
	conns := make([]*conn, 0, len(n.conns))
	for _, c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		_ = c.send(fin)
		n.logf("wire ► FIN       op%d → op%d  (finished, draining)", n.self, c.peer)
	}
	// Wait for every peer's FIN.
	got := make(map[int]bool, len(conns))
	deadline := time.After(timeout)
	for len(got) < len(conns) {
		select {
		case from := <-n.finCh:
			got[from] = true
		case <-deadline:
			return
		}
	}
}

// Close tears down all connections.
func (n *Network) Close() {
	n.once.Do(func() { close(n.closed) })
	n.mu.Lock()
	for _, c := range n.conns {
		_ = c.nc.Close()
	}
	n.mu.Unlock()
}

func pubEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- tiny framed-byte helpers for the handshake (separate from Envelope) ---

func frameBytes(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

func readFrameBytes(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 1<<16 {
		return nil, fmt.Errorf("bad handshake frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

type hello struct {
	From   int    `json:"from"`
	PubKey []byte `json:"pubkey"`
	Nonce  []byte `json:"nonce"`
}

func writeHello(w io.Writer, from int, pub ed25519.PublicKey, nonce []byte) error {
	h := hello{From: from, PubKey: pub, Nonce: nonce}
	return writeJSON(w, h)
}

func readHello(r io.Reader) (int, ed25519.PublicKey, []byte, error) {
	var h hello
	if err := readJSON(r, &h); err != nil {
		return -1, nil, nil, err
	}
	if len(h.PubKey) != ed25519.PublicKeySize || len(h.Nonce) != 32 {
		return -1, nil, nil, fmt.Errorf("bad hello fields")
	}
	return h.From, ed25519.PublicKey(h.PubKey), h.Nonce, nil
}
