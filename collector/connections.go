package collector

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/prometheus/client_golang/prometheus"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

type connectionMessage struct {
	DownloadTotal int64         `json:"downloadTotal"`
	UploadTotal   int64         `json:"uploadTotal"`
	Connections   []Connections `json:"connections"`
}

type Metadata struct {
	Network         string `json:"network"`
	Type            string `json:"type"`
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	Host            string `json:"host"`
	DNSMode         string `json:"dnsMode"`
	ProcessPath     string `json:"processPath"`
	SpecialProxy    string `json:"specialProxy"`
}
type Connections struct {
	ID          string    `json:"id"`
	Metadata    Metadata  `json:"metadata"`
	Upload      int       `json:"upload"`
	Download    int       `json:"download"`
	Start       time.Time `json:"start"`
	Chains      []string  `json:"chains"`
	Rule        string    `json:"rule"`
	RulePayload string    `json:"rulePayload"`
}
type cacheEntry struct {
	hostname  string    // 缓存的值，这里是IP地址解析出的主机名
	expiresAt time.Time // 条目的过期时间
}

var (
	uploadTotal         *prometheus.GaugeVec
	downloadTotal       *prometheus.GaugeVec
	activeConnections   *prometheus.GaugeVec
	networkTrafficTotal *prometheus.CounterVec
	ipToHostnameCache   sync.Map // 使用sync.Map, 它是线程安全的
)

type Connection struct {
	connectionCache map[string]Connections
}

// LookupHostnameWithCache 尝试从缓存中获取主机名，如果没有找到，它会查询DNS并更新缓存
// 修改LookupHostnameWithCache函数来检查缓存条目是否过期
func LookupHostnameWithCache(ip string) (string, error) {
	if entry, ok := ipToHostnameCache.Load(ip); ok {
		cachedEntry := entry.(cacheEntry)
		return cachedEntry.hostname, nil
	}
	// 缓存中没有找到或条目已过期，执行DNS查询
	hostnames, err := net.LookupAddr(ip)
	if err != nil {
		ipToHostnameCache.Store(ip, cacheEntry{
			hostname:  "",
			expiresAt: time.Now().Add(10 * time.Minute),
		})
		return "", err
	}
	if len(hostnames) > 0 {
		hostname := hostnames[0]
		// 创建一个新的缓存条目，设置过期时间为10分钟后
		ipToHostnameCache.Store(ip, cacheEntry{
			hostname:  hostname,
			expiresAt: time.Now().Add(10 * time.Minute),
		})
		return hostname, nil
	}
	return "", nil
}

// StartCacheCleanup 定期清理过期的缓存条目
func StartCacheCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			<-ticker.C
			now := time.Now()
			ipToHostnameCache.Range(func(key, value interface{}) bool {
				// 检查每个条目是否过期
				entry := value.(cacheEntry)
				if now.After(entry.expiresAt) {
					// 如果过期了，就删除
					ipToHostnameCache.Delete(key)
					log.Println("清理ip-hostname缓存:", key)
				}
				return true // 继续遍历
			})
		}
	}()
}

func (c *Connection) Name() string {
	return "connections"
}

func (c *Connection) Collect(config CollectConfig) error {
	log.Println("starting collector:", c.Name())
	ctx := context.Background()
	endpoint := fmt.Sprintf("ws://%s/connections", config.ClashHost)
	if config.ClashToken != "" {
		endpoint = fmt.Sprintf("%s?token=%s", endpoint, config.ClashToken)
	}
	conn, _, err := websocket.Dial(ctx, endpoint, nil)
	if err != nil {
		log.Fatal("failed to dial: ", err)
	}

	conn.SetReadLimit(10 * 1024 * 1024)

	defer conn.Close(websocket.StatusInternalError, "the sky is falling")
	for {
		var m connectionMessage
		err = wsjson.Read(ctx, conn, &m)
		if err != nil {
			return errors.Wrap(err, "failed to read JSON message")
		}
		uploadTotal.WithLabelValues().Set(float64(m.UploadTotal))
		downloadTotal.WithLabelValues().Set(float64(m.DownloadTotal))
		activeConnections.WithLabelValues().Set(float64(len(m.Connections)))
		activeConnectionsMap := make(map[string]interface{})
		for _, connection := range m.Connections {
			if _, ok := c.connectionCache[connection.ID]; !ok {
				c.connectionCache[connection.ID] = Connections{
					Upload:   0,
					Download: 0,
				}
			}
			destination := connection.Metadata.Host
			if destination == "" {
				destination = connection.Metadata.DestinationIP
			}
			if !config.CollectDest {
				destination = ""
			}
			sourceHostName, _ := LookupHostnameWithCache(connection.Metadata.SourceIP)
			networkTrafficTotal.WithLabelValues(connection.Metadata.SourceIP, sourceHostName, destination, connection.Chains[0], "download").Add(float64(connection.Download) - float64(c.connectionCache[connection.ID].Download))
			networkTrafficTotal.WithLabelValues(connection.Metadata.SourceIP, sourceHostName, destination, connection.Chains[0], "upload").Add(float64(connection.Upload) - float64(c.connectionCache[connection.ID].Upload))
			c.connectionCache[connection.ID] = connection
			activeConnectionsMap[connection.ID] = nil
		}
		for id := range c.connectionCache {
			if _, ok := activeConnectionsMap[id]; !ok {
				delete(c.connectionCache, id)
			}
		}
	}
}

func init() {
	uploadTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "clash",
			Name:      "upload_bytes_total",
			Help:      "Total upload bytes",
		},
		[]string{},
	)
	downloadTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "clash",
			Name:      "download_bytes_total",
			Help:      "Total download bytes",
		},
		[]string{},
	)

	activeConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "clash",
			Name:      "active_connections",
			Help:      "Active connections",
		},
		[]string{},
	)

	networkTrafficTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clash",
			Name:      "network_traffic_bytes_total",
			Help:      "Total number of bytes downloaded/uploaded, categorized by source, destination, and policy.",
		},
		[]string{"source", "source_name", "destination", "policy", "type"},
	)

	prometheus.MustRegister(uploadTotal, downloadTotal, activeConnections, networkTrafficTotal)

	c := &Connection{connectionCache: map[string]Connections{}}
	Register(c)
	// 启动缓存清理，例如每1分钟清理一次
	StartCacheCleanup(1 * time.Minute)
}
