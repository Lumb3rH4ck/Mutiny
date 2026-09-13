package torrent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"golang.org/x/time/rate"
)

// SeedConfig tunes the SeedEngine, a separate anacrolix client dedicated to
// re-seeding delivered previous downloads from their clean/ folders.
type SeedConfig struct {
	DataDir       string
	ListenPort    int
	DHTEnabled    bool
	UploadRateBps int64
	BindIface     string
}

// SeedEngine re-seeds completed torrents whose data was delivered to a clean/
// root, without touching the download client. It runs its own anacrolix client
// configured Seed=true (anacrolix has no per-torrent seeding switch), keeps a
// stable listen port + DHT so peers can find us again, and opens the seeds'
// sockets under the same VPN device the download client uses.
type SeedEngine struct {
	client  *torrent.Client
	dataDir string
	// uploadLimiter is the same *rate.Limiter handed to the client config, so
	// SetUploadRate can retune the live cap (the client copies the config
	// struct but keeps the limiter pointer).
	uploadLimiter *rate.Limiter

	mu     sync.Mutex
	active map[string]bool
}

// NewSeedEngine starts the seeding client. The main client and the seed client
// cannot share a UDP listen port, so ListenPort must differ from the download
// client's TorrentPort.
func NewSeedEngine(cfg SeedConfig) (*SeedEngine, error) {
	cc := torrent.NewDefaultClientConfig()
	cc.DataDir = cfg.DataDir
	cc.ListenPort = cfg.ListenPort
	cc.NoDHT = !cfg.DHTEnabled
	cc.Seed = true
	cc.Logger = newClientLogger()
	uploadLimiter := rate.NewLimiter(rate.Inf, 16384)
	if cfg.UploadRateBps > 0 {
		uploadLimiter.SetLimit(rate.Limit(cfg.UploadRateBps))
	}
	cc.UploadRateLimiter = uploadLimiter
	cc.DownloadRateLimiter = rate.NewLimiter(rate.Inf, 16384)

	if cfg.BindIface != "" {
		v4, v6, err := vpnBindResolver(cfg.BindIface)
		if err != nil {
			return nil, err
		}
		cc.ListenHost = func(network string) string { return vpnListenHostAddr(network, v4, v6) }
		cc.DisableTCP = true
		cc.DisableIPv6 = v6 == nil
	}

	client, err := torrent.NewClient(cc)
	if err != nil {
		return nil, fmt.Errorf("create seed client: %w", err)
	}

	if cfg.BindIface != "" {
		for _, network := range []string{"tcp4", "tcp6"} {
			client.AddDialer(vpnBindDialer{network: network, iface: cfg.BindIface})
		}
	}

	return &SeedEngine{
		client:        client,
		dataDir:       cfg.DataDir,
		uploadLimiter: uploadLimiter,
		active:        make(map[string]bool),
	}, nil
}

// AddTorrentBytes registers the delivered data identified by the bencoded
// metainfo (captured at completion) for re-seeding. It verifies the delivered
// files actually exist under DataDir first — anacrolix would otherwise create
// empty placeholder files for missing data — and refuses to download anything:
// this engine only uploads what is already on disk. Returns the torrent
// infohash hex id.
func (e *SeedEngine) AddTorrentBytes(raw []byte) (string, error) {
	mi, err := metainfo.Load(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("load seed metainfo: %w", err)
	}
	info, err := mi.UnmarshalInfo()
	if err != nil {
		return "", fmt.Errorf("decode seed metainfo: %w", err)
	}
	if err := e.checkDelivered(info); err != nil {
		return "", err
	}

	spec, err := torrent.TorrentSpecFromMetaInfoErr(mi)
	if err != nil {
		return "", fmt.Errorf("build seed spec: %w", err)
	}
	spec.DisallowDataDownload = true

	t, _, err := e.client.AddTorrentSpec(spec)
	if err != nil {
		return "", fmt.Errorf("add seed torrent: %w", err)
	}
	id := t.InfoHash().HexString()
	e.mu.Lock()
	e.active[id] = true
	e.mu.Unlock()
	return id, nil
}

func (e *SeedEngine) checkDelivered(info metainfo.Info) error {
	if !info.IsDir() {
		p := filepath.Join(e.dataDir, info.Name)
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("delivered data not found for seeding: %s", p)
		}
		return nil
	}
	root := filepath.Join(e.dataDir, info.Name)
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("delivered data not found for seeding: %s", root)
	}
	return nil
}

// Remove drops a single torrent from the seed client. The per-item Seeding
// marker in the state store is NOT touched here — the caller manages it.
func (e *SeedEngine) Remove(id string) error {
	var ih metainfo.Hash
	if err := ih.FromHexString(id); err != nil {
		return fmt.Errorf("remove seed %s: %w", id, err)
	}
	t, ok := e.client.Torrent(ih)
	if ok {
		t.Drop()
	}
	e.mu.Lock()
	delete(e.active, id)
	e.mu.Unlock()
	return nil
}

// IsActive reports whether a torrent with this infohash is registered in the
// seed client (may be seeding or still verifying pieces).
func (e *SeedEngine) IsActive(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.active[id]
}

// DrainAll drops every registered seed from the client (e.g. during VPN
// panic so no seed traffic leaks off the tunnel). The per-item markers and
// metainfo stay persisted, so ReseedAll brings them back.
func (e *SeedEngine) DrainAll() {
	for _, t := range e.client.Torrents() {
		t.Drop()
	}
	e.mu.Lock()
	e.active = make(map[string]bool)
	e.mu.Unlock()
}

// SetUploadRate bounds the aggregate upload from the seed client live (0 or
// negative = unlimited).
func (e *SeedEngine) SetUploadRate(bps int64) {
	if bps > 0 {
		e.uploadLimiter.SetLimit(rate.Limit(bps))
	} else {
		e.uploadLimiter.SetLimit(rate.Inf)
	}
}

func (e *SeedEngine) Close() error {
	return errors.Join(e.client.Close()...)
}
