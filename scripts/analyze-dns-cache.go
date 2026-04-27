//go:build ignore

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/miekg/dns"
	"github.com/vmihailenco/msgpack/v5"
)

var bucketDNSCache = []byte("dns-cache")

type dnsCacheRecord struct {
	Msg    []byte
	Expire time.Time
}

type cacheEntry struct {
	Namespace string    `json:"namespace"`
	Key       string    `json:"key"`
	Expire    time.Time `json:"expire"`
	TTL       int64     `json:"ttl_seconds"`
	Expired   bool      `json:"expired"`
	Rcode     string    `json:"rcode"`
	Question  []string  `json:"question"`
	Answer    []string  `json:"answer"`
	NS        []string  `json:"ns"`
	Extra     []string  `json:"extra"`
	Error     string    `json:"error,omitempty"`
}

func main() {
	dbPath := flag.String("db", defaultDNSCachePath(), "path to dns-cache.db")
	jsonOutput := flag.Bool("json", false, "print entries as JSON")
	fullOutput := flag.Bool("full", false, "print full DNS records instead of a compact summary")
	activeOnly := flag.Bool("active-only", false, "hide expired entries")
	limit := flag.Int("limit", 3, "maximum records to show per DNS section in table mode")
	flag.Parse()

	entries, err := loadEntries(*dbPath, *fullOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read DNS cache failed: %v\n", err)
		os.Exit(1)
	}

	if *activeOnly {
		filtered := entries[:0]
		for _, entry := range entries {
			if !entry.Expired {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(entries); err != nil {
			fmt.Fprintf(os.Stderr, "encode JSON failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	printTable(entries, *limit)
}

func defaultDNSCachePath() string {
	if homeDir := os.Getenv("CLASH_HOME_DIR"); homeDir != "" {
		return filepath.Join(homeDir, "dns-cache.db")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir, _ = os.Getwd()
	}

	defaultHome := filepath.Join(homeDir, ".config", "mihomo")
	if _, err := os.Stat(defaultHome); err == nil {
		return filepath.Join(defaultHome, "dns-cache.db")
	}

	if configHome := os.Getenv("XDG_CONFIG_HOME"); configHome != "" {
		return filepath.Join(configHome, "mihomo", "dns-cache.db")
	}
	return filepath.Join(defaultHome, "dns-cache.db")
}

func loadEntries(dbPath string, fullOutput bool) ([]cacheEntry, error) {
	db, err := bbolt.Open(dbPath, 0o666, &bbolt.Options{
		ReadOnly: true,
		Timeout:  time.Second,
	})
	if err != nil {
		return nil, err
	}
	defer db.Close()

	now := time.Now()
	var entries []cacheEntry
	err = db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket(bucketDNSCache)
		if root == nil {
			return nil
		}

		return root.ForEach(func(namespaceBytes, _ []byte) error {
			namespace := string(namespaceBytes)
			bucket := root.Bucket(namespaceBytes)
			if bucket == nil {
				return nil
			}

			return bucket.ForEach(func(keyBytes, value []byte) error {
				key := string(keyBytes)
				entry := cacheEntry{
					Namespace: namespace,
					Key:       key,
				}

				var record dnsCacheRecord
				if err := msgpack.Unmarshal(value, &record); err != nil {
					entry.Error = err.Error()
					entries = append(entries, entry)
					return nil
				}

				entry.Expire = record.Expire
				entry.TTL = int64(time.Until(record.Expire).Seconds())
				entry.Expired = !record.Expire.After(now)

				msg := &dns.Msg{}
				if err := msg.Unpack(record.Msg); err != nil {
					entry.Error = err.Error()
					entries = append(entries, entry)
					return nil
				}

				entry.Rcode = dns.RcodeToString[msg.Rcode]
				entry.Question = questions(msg.Question)
				entry.Answer = records(msg.Answer, fullOutput)
				entry.NS = records(msg.Ns, fullOutput)
				entry.Extra = records(msg.Extra, fullOutput)
				entries = append(entries, entry)
				return nil
			})
		})
	})
	return entries, err
}

func questions(records []dns.Question) []string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, record.String())
	}
	return out
}

func records(records []dns.RR, fullOutput bool) []string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		if fullOutput {
			out = append(out, record.String())
			continue
		}
		header := record.Header()
		out = append(out, fmt.Sprintf("%s %s ttl=%d", header.Name, dns.TypeToString[header.Rrtype], header.Ttl))
	}
	return out
}

func printTable(entries []cacheEntry, limit int) {
	fmt.Printf("entries: %d\n\n", len(entries))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAMESPACE\tSTATE\tTTL\tEXPIRE\tKEY\tRCODE\tQUESTION\tANSWER")
	for _, entry := range entries {
		state := "active"
		if entry.Expired {
			state = "expired"
		}
		if entry.Error != "" {
			state = "error"
		}

		answer := entry.Error
		if answer == "" {
			answer = joinLimited(entry.Answer, limit)
		}

		fmt.Fprintf(
			w,
			"%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			entry.Namespace,
			state,
			entry.TTL,
			entry.Expire.Format(time.RFC3339),
			entry.Key,
			entry.Rcode,
			strings.Join(entry.Question, " | "),
			answer,
		)
	}
	_ = w.Flush()
}

func joinLimited(values []string, limit int) string {
	if len(values) == 0 {
		return "-"
	}
	if limit <= 0 || len(values) <= limit {
		return strings.Join(values, " | ")
	}
	return strings.Join(values[:limit], " | ") + fmt.Sprintf(" | ... +%d", len(values)-limit)
}
