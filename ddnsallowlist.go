// Package ddns_allowlist dynamic DNS allowlist
//
//revive:disable-next-line:var-naming
//nolint:stylecheck
package ddns_allowlist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Imaskiller/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/config/dynamic"
	"github.com/Imaskiller/ddns-allowlist/pkg/github.com/traefik/traefik/pkg/ip"
	logger "github.com/Imaskiller/ddns-allowlist/pkg/log"
)

const (
	typeName              = "ddns-allowlist"
	defaultLookupInterval = 5 * time.Minute
	// Maximum number of retries for DNS resolution
	maxDNSRetries = 3
	// Delay between DNS resolution retries
	dnsRetryDelay = 2 * time.Second
	// Default TTL for DNS cache entries
	defaultDNSTTL = 5 * time.Minute
	// Initial timeout for DNS queries
	initialDNSTimeout = 8 * time.Second
	// Subsequent timeout for DNS queries
	subsequentDNSTimeout = 5 * time.Second
)

// Define static error variable.
var (
	errEmptySourceRangeHosts   = errors.New("sourceRangeHosts is empty, DDNSAllowLister not created")
	errInvalidHTTPStatuscode   = errors.New("invalid HTTP status code")
	errNoIPAddressFoundForHost = errors.New("no IP addresses found for hostname")
	errDNSResolutionFailed     = errors.New("DNS resolution failed after retries")
	errInvalidDNSResolver      = errors.New("invalid DNS resolver address")
)

// DNSCacheEntry represents a cached DNS resolution result
type DNSCacheEntry struct {
	IPs      []string
	ExpireAt time.Time
}

// DdnsAllowListConfig holds the DDNS allowlist middleware plugin configuration.
// This middleware limits allowed requests based on the client IP on a given hostname.
// More info: https://github.com/Imaskiller/ddns-allowlist
type DdnsAllowListConfig struct {
	// SourceRange defines the set of allowed IPs (or ranges of allowed IPs by using CIDR notation).
	SourceRangeHosts []string            `json:"sourceRangeHosts,omitempty"`
	SourceRangeIPs   []string            `json:"sourceRangeIps,omitempty"`
	IPStrategy       *dynamic.IPStrategy `json:"ipStrategy,omitempty"`
	// RejectStatusCode defines the HTTP status code used for refused requests.
	// If not set, the default is 403 (Forbidden).
	RejectStatusCode int `json:"rejectStatusCode,omitempty"`
	// LogLevel defines on what level the middleware plugin should print log messages (DEBUG, INFO, ERROR).
	LogLevel string `json:"logLevel,omitempty"`
	// Lookup interval for new hostnames in seconds
	LookupInterval int64 `json:"lookupInterval,omitempty"`
	// AllowedIPv6InterfaceIdentifierPrefix defines the prefix used to allow IPv6 addresses to be whitelisted.
	// This will only check the network prefix and skip the interface identifier.
	// Used to allow subnetworks or hosts behind a IPv6 router.
	// (default: disabled (0), allowed range: 0-128)
	AllowedIPv6NetworkPrefix int `json:"allowedIPv6NetworkPrefix,omitempty"`
	// DNS cache TTL in seconds
	DNSCacheTTL int64 `json:"dnsCacheTTL,omitempty"`
}

// ddnsAllowLister is a middleware that provides Checks of the Requesting IP against a set of Allowlists generated from DNS hostnames.
type ddnsAllowLister struct {
	next              http.Handler
	allowLister       *ip.Checker
	strategy          ip.Strategy
	name              string
	rejectStatusCode  int
	logger            *logger.Logger
	lastUpdate        time.Time
	mu                sync.RWMutex
	sourceRangeHosts  []string
	sourceRangeIPs    []string
	lookupInterval    time.Duration
	networkPrefixIPv6 int
	dnsCache          map[string]DNSCacheEntry
	dnsCacheTTL       time.Duration
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *DdnsAllowListConfig {
	return &DdnsAllowListConfig{}
}

// New created a new DDNSallowlist plugin.
func New(_ context.Context, next http.Handler, config *DdnsAllowListConfig, name string) (http.Handler, error) {
	logger := logger.NewLogger(config.LogLevel, name, typeName)
	logger.Debug("Creating middleware")

	if len(config.SourceRangeHosts) == 0 {
		return nil, errEmptySourceRangeHosts
	}

	rejectStatusCode := config.RejectStatusCode
	// If RejectStatusCode is not given, default to Forbidden (403).
	if rejectStatusCode == 0 {
		rejectStatusCode = http.StatusForbidden
	} else if http.StatusText(rejectStatusCode) == "" {
		return nil, fmt.Errorf("%w: %d", errInvalidHTTPStatuscode, rejectStatusCode)
	}

	strategy, err := config.IPStrategy.Get()
	if err != nil {
		return nil, err
	}
	logger.Debugf("using strategy: %v", strategy.Name())

	lookupInterval := defaultLookupInterval
	if config.LookupInterval > 0 {
		lookupInterval = time.Duration(config.LookupInterval) * time.Second
	}

	dnsCacheTTL := defaultDNSTTL
	if config.DNSCacheTTL > 0 {
		dnsCacheTTL = time.Duration(config.DNSCacheTTL) * time.Second
	}

	// Initialize the ddnsAllowLister
	dal := &ddnsAllowLister{
		strategy:          strategy,
		next:              next,
		name:              name,
		rejectStatusCode:  rejectStatusCode,
		logger:            logger,
		sourceRangeHosts:  config.SourceRangeHosts,
		sourceRangeIPs:    config.SourceRangeIPs,
		lookupInterval:    lookupInterval,
		networkPrefixIPv6: config.AllowedIPv6NetworkPrefix,
		dnsCache:          make(map[string]DNSCacheEntry),
		dnsCacheTTL:       dnsCacheTTL,
	}

	// Initial update of trusted IPs
	dal.mu.Lock()
	err = dal.updateTrustedIPs()
	dal.mu.Unlock()
	if err != nil {
		return nil, err
	}

	return dal, nil
}

// updateTrustedIPs updates the trusted IPs by resolving the hostnames and combining with the provided IP ranges.
// This function assumes the caller holds the write lock.
func (dal *ddnsAllowLister) updateTrustedIPs() error {
	dal.logger.Debug("Updating trusted IPs")
	trustedIPs := []string{}

	// Set a timeout for the entire update operation - increase from 30s to 60s
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Use a channel to collect results with a timeout
	type lookupResult struct {
		ips []string
		err error
	}

	resultChan := make(chan lookupResult, 1)

	go func() {
		hostIPs := dal.resolveHostsWithCache()
		resultChan <- lookupResult{ips: hostIPs}
	}()

	// Wait for results or timeout
	select {
	case result := <-resultChan:
		trustedIPs = append(trustedIPs, result.ips...)
	case <-ctx.Done():
		dal.logger.Errorf("Timeout while resolving hosts: %v", ctx.Err())

		// On timeout, try to use any available cache entries.
		// The caller (e.g., from New() or ServeHTTP's goroutine)
		// is responsible for holding the write lock (dal.mu).
		for host, entry := range dal.dnsCache {
			dal.logger.Infof("Using cached IPs for %s due to timeout", host)
			trustedIPs = append(trustedIPs, entry.IPs...)
		}
	}

	// Always include the static IPs even if DNS resolution failed
	trustedIPs = append(trustedIPs, dal.sourceRangeIPs...)

	// If we have no trusted IPs at all, keep the old ones
	if len(trustedIPs) == 0 {
		dal.logger.Debug("No trusted IPs found, keeping existing configuration")
		return nil
	}

	dal.logger.Debugf("trusted IPs: %v", trustedIPs)

	checker, err := ip.NewChecker(trustedIPs, dal.networkPrefixIPv6)
	if err != nil {
		return err
	}

	dal.lastUpdate = time.Now()
	dal.allowLister = checker
	return nil
}

// resolveHostsWithCache resolves hosts using cache when available
func (dal *ddnsAllowLister) resolveHostsWithCache() []string {
	hostIPs := []string{}
	now := time.Now()

	// Clean expired cache entries
	dal.cleanExpiredCacheEntries()

	// Set a timeout for the entire operation - increase from 20s to 45s
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Process each host with a timeout
	for _, host := range dal.sourceRangeHosts {
		// Check if the overall timeout has been reached
		if ctx.Err() != nil {
			dal.logger.Debugf("Overall timeout reached while resolving hosts: %v", ctx.Err())

			// When timeout occurs, try to use any available cache entries
			for _, h := range dal.sourceRangeHosts {
				if entry, found := dal.dnsCache[h]; found {
					dal.logger.Infof("Using cache entry for host %s due to timeout", h)
					hostIPs = append(hostIPs, entry.IPs...)
				}
			}

			// If we found cached IPs, return them
			if len(hostIPs) > 0 {
				dal.logger.Infof("Returning %d cached IPs after timeout", len(hostIPs))
				return hostIPs
			}

			// Otherwise, break and continue with empty list
			break
		}

		// Check if we have a valid cache entry
		cacheEntry, found := dal.dnsCache[host]

		if found && now.Before(cacheEntry.ExpireAt) {
			timeRemaining := cacheEntry.ExpireAt.Sub(now).Round(time.Second)
			dal.logger.Debugf("Cache HIT for host %s: using cached IPs (expires in %v): %v",
				host, timeRemaining, cacheEntry.IPs)
			hostIPs = append(hostIPs, cacheEntry.IPs...)
			continue
		}

		// Log cache miss or expiration
		if !found {
			dal.logger.Debugf("Cache MISS for host %s: no cache entry found", host)
		} else {
			timeSinceExpiry := now.Sub(cacheEntry.ExpireAt).Round(time.Second)
			dal.logger.Debugf("Cache EXPIRED for host %s: cache entry expired %v ago",
				host, timeSinceExpiry)
		}

		// Cache miss or expired, resolve the host with a timeout - increase from 10s to 15s
		hostCtx, hostCancel := context.WithTimeout(ctx, 15*time.Second)

		// Use a channel to collect results with a timeout
		type lookupResult struct {
			ips []string
			err error
		}

		resultChan := make(chan lookupResult, 1)

		go func() {
			ips, err := dal.resolveHostWithRetry(host)
			select {
			case resultChan <- lookupResult{ips: ips, err: err}:
				// Result sent successfully
			case <-hostCtx.Done():
				// Context cancelled, no need to send result
			}
		}()

		// Wait for results or timeout
		var ips []string
		var err error

		select {
		case result := <-resultChan:
			ips = result.ips
			err = result.err
		case <-hostCtx.Done():
			dal.logger.Debugf("Timeout while resolving host %s: %v", host, hostCtx.Err())
			err = fmt.Errorf("timeout resolving host: %w", hostCtx.Err())
		}

		hostCancel() // Cancel the context to clean up resources

		if err != nil {
			dal.logger.Errorf("Failed to resolve host %s: %v", host, err)

			// If we have a stale cache entry, use it as fallback
			if found {
				timeSinceExpiry := now.Sub(cacheEntry.ExpireAt).Round(time.Second)
				dal.logger.Infof("Using stale cache entry for host %s as fallback (expired %v ago): %v",
					host, timeSinceExpiry, cacheEntry.IPs)
				hostIPs = append(hostIPs, cacheEntry.IPs...)
			} else {
				dal.logger.Debugf("No cache entry available for host %s and resolution failed - host will be inaccessible", host)
			}
			continue
		}

		// Update cache with new IPs
		dal.dnsCache[host] = DNSCacheEntry{
			IPs:      ips,
			ExpireAt: now.Add(dal.dnsCacheTTL),
		}
		dal.logger.Debugf("Cache UPDATED for host %s: stored new IPs with TTL %v: %v",
			host, dal.dnsCacheTTL, ips)

		hostIPs = append(hostIPs, ips...)
	}

	return hostIPs
}

// cleanExpiredCacheEntries removes expired entries from the DNS cache
func (dal *ddnsAllowLister) cleanExpiredCacheEntries() {
	now := time.Now()

	// Use a write lock since we're modifying the cache
	// dal.mu.Lock() // Lock removed, G_update in ServeHTTP or New() is expected to hold the WLock
	// defer dal.mu.Unlock() // Lock removed

	// Set a limit on how many entries to clean in one go to avoid blocking too long
	cleanCount := 0
	maxCleanCount := 100

	for host, entry := range dal.dnsCache {
		if cleanCount >= maxCleanCount {
			dal.logger.Debugf("Reached clean limit of %d entries, will clean more next time", maxCleanCount)
			break
		}

		if now.After(entry.ExpireAt) {
			dal.logger.Debugf("Removing expired cache entry for host %s", host)
			delete(dal.dnsCache, host)
			cleanCount++
		}
	}
}

// resolveHostWithRetry attempts to resolve a hostname with retries
func (dal *ddnsAllowLister) resolveHostWithRetry(host string) ([]string, error) {
	var ips []string
	var err error
	allErrors := make([]error, 0, maxDNSRetries)

	dal.logger.Debugf("Starting DNS resolution for host %s", host)

	// Set an overall timeout for the entire resolution process
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for attempt := 0; attempt < maxDNSRetries; attempt++ {
		// Check if the overall timeout has been reached
		if ctx.Err() != nil {
			dal.logger.Debugf("Overall timeout reached for host %s after %d attempts", host, attempt)
			break
		}

		if attempt > 0 {
			dal.logger.Debugf("Retrying DNS resolution for host %s (attempt %d/%d)", host, attempt+1, maxDNSRetries)
			time.Sleep(dnsRetryDelay)
		} else {
			dal.logger.Debugf("Attempting DNS resolution for host %s (attempt %d/%d)", host, attempt+1, maxDNSRetries)
		}

		var lookupIPs []net.IP
		var lookupErr error

		// Use custom resolver if configured, otherwise use the system default
		resolverType := "system default"
		startTime := time.Now()

		// Always use system resolver with timeout:
		queryCtx, queryCancel := context.WithTimeout(ctx, subsequentDNSTimeout)
		lookupIPs, lookupErr = net.DefaultResolver.LookupIP(queryCtx, "ip", host)
		queryCancel()

		elapsedTime := time.Since(startTime)

		if lookupErr == nil {
			// Success, convert IPs to strings
			for _, lookupIP := range lookupIPs {
				ips = append(ips, lookupIP.String())
			}

			if len(ips) > 0 {
				resolverInfo := resolverType

				dal.logger.Infof("Successfully resolved host %s using %s resolver in %v: %v",
					host, resolverInfo, elapsedTime.Round(time.Millisecond), ips)
				dal.logger.Tracef("DNS resolution details for %s: resolver=%s, attempts=%d/%d, time=%v",
					host, resolverInfo, attempt+1, maxDNSRetries, elapsedTime.Round(time.Microsecond))
				return ips, nil
			}
		} else {
			err = lookupErr
			allErrors = append(allErrors, lookupErr)

			resolverInfo := resolverType

			dal.logger.Errorf("Error looking up IP for host %s (attempt %d/%d, resolver=%s, time=%v): %v",
				host, attempt+1, maxDNSRetries, resolverInfo, elapsedTime.Round(time.Millisecond), lookupErr)
		}

		// Check if we've been cancelled
		if ctx.Err() != nil {
			dal.logger.Debugf("DNS resolution for host %s cancelled: %v", host, ctx.Err())
			break
		}
	}

	if len(ips) == 0 {
		if err != nil {
			// Include information about all errors encountered
			errMsg := fmt.Sprintf("%w: %s: %v", errDNSResolutionFailed, host, err)
			if len(allErrors) > 1 {
				errMsg += fmt.Sprintf(" (additional errors: %v)", allErrors[1:])
			}
			return nil, errors.New(errMsg)
		}
		return nil, fmt.Errorf("%w: %s", errNoIPAddressFoundForHost, host)
	}

	return ips, nil
}

// ServeHTTP ddnsallowlist.
func (dal *ddnsAllowLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := dal.logger
	logger.Debug("Serving middleware")
	logger.Tracef("Incoming request: %+v", req)

	// Check if the trusted IPs need to be updated
	dal.mu.RLock()
	needsUpdate := time.Since(dal.lastUpdate) > dal.lookupInterval
	dal.mu.RUnlock()

	if needsUpdate {
		// Use a separate goroutine for updates to prevent blocking requests
		// This ensures we don't hold up the current request if DNS resolution is slow
		go func() {
			// Acquire write lock for the update
			dal.mu.Lock()
			defer dal.mu.Unlock()

			// Double-check after acquiring write lock
			if time.Since(dal.lastUpdate) > dal.lookupInterval {
				err := dal.updateTrustedIPs()
				if err != nil {
					logger.Errorf("Failed to update trusted IPs: %v", err)
					// Continue with existing IPs - don't block requests
				}
			}
		}()
	}

	// Get the client IP and check if it's authorized
	clientIP := dal.strategy.GetIP(req)

	// Use read lock to check authorization
	dal.mu.RLock()
	err := dal.allowLister.IsAuthorized(clientIP)
	dal.mu.RUnlock()

	if err != nil {
		logger.Debugf("Rejecting IP %s: %v", clientIP, err)
		reject(logger, dal.rejectStatusCode, rw)
		return
	}
	logger.Debugf("Accepting IP %s", clientIP)

	dal.next.ServeHTTP(rw, req)
}

func reject(logger *logger.Logger, statusCode int, rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		logger.Error(err)
	}
}
