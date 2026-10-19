package crypto

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/MastewalB/behemoth/errs"
)

// KeySource gives a key set its keys: fetched over the network, read from a
// file, or computed. It returns the keys as they are when it is called, and
// caches nothing. keysource.JWKSet is one, for a JWK set at a URL.
type KeySource interface {
	// Keys returns the keys of the set. An error is a failure of the
	// system, never a refused token.
	Keys(ctx context.Context) ([]PublishedKey, error)
}

// Defaults of CacheOptions.
const (
	// DefaultKeySetTTL is how long fetched keys are used before they are
	// fetched again. It is the max-age behemoth's own key set route sends.
	DefaultKeySetTTL = 5 * time.Minute
	// DefaultKeyRefetchInterval is the shortest time between two fetches.
	DefaultKeyRefetchInterval = time.Minute
	// DefaultKeySetMaxStale is how long past their TTL keys are used while
	// the source fails.
	DefaultKeySetMaxStale = time.Hour
)

// CacheOptions configures a CachedKeySet. The zero value gives the
// defaults.
type CacheOptions struct {
	// TTL is how long fetched keys are used before the next call fetches
	// them again. Zero means DefaultKeySetTTL.
	TTL time.Duration

	// RefetchInterval is the shortest time between two fetches, whatever
	// causes them: the TTL, a token that names a kid the keys lack, or a
	// retry after the source failed. A token with a made-up kid can't make
	// the set fetch more often than this. Zero means
	// DefaultKeyRefetchInterval.
	RefetchInterval time.Duration

	// MaxStale is how long past TTL the keys keep being used while the
	// source fails, so that tokens are still checked while the issuer's
	// key set can't be reached. Zero means DefaultKeySetMaxStale, and a
	// negative value means none: a failed fetch then fails every token.
	MaxStale time.Duration

	// Now is the clock, for tests. Nil means time.Now.
	Now func() time.Time
}

// Validate reports an option that can't work: a negative TTL or
// RefetchInterval.
func (o CacheOptions) Validate() error {
	if o.TTL < 0 {
		return fmt.Errorf("CacheOptions.TTL is negative: %s", o.TTL)
	}
	if o.RefetchInterval < 0 {
		return fmt.Errorf("CacheOptions.RefetchInterval is negative: %s", o.RefetchInterval)
	}
	return nil
}

func (o CacheOptions) withDefaults() CacheOptions {
	if o.TTL == 0 {
		o.TTL = DefaultKeySetTTL
	}
	if o.RefetchInterval == 0 {
		o.RefetchInterval = DefaultKeyRefetchInterval
	}
	if o.MaxStale == 0 {
		o.MaxStale = DefaultKeySetMaxStale
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// CachedKeySet is a KeySet over a KeySource: the keys the source last
// returned, fetched again when they are older than the TTL, or when a token
// names a kid they lack. It is safe for concurrent use. A call that has to
// fetch holds the others until the source answers.
//
// A source's error is a failure of the system. While the source fails, keys
// fetched less than TTL plus MaxStale ago keep being used. A token whose kid
// the keys lack is refused once they were fetched again, or fetched less
// than RefetchInterval ago.
type CachedKeySet struct {
	src  KeySource
	opts CacheOptions

	mu        sync.Mutex
	keys      []PublishedKey
	fetchedAt time.Time // the last fetch that succeeded; zero before the first
	triedAt   time.Time // the last fetch, whatever its result
	lastErr   error     // the error of the last fetch; nil when it succeeded
}

var _ KeySet = (*CachedKeySet)(nil)

// NewCachedKeySet returns a key set over src with opts. It fetches nothing
// yet: the first call that needs a key does. A nil src and options that
// fail Validate are configuration errors.
func NewCachedKeySet(src KeySource, opts CacheOptions) (*CachedKeySet, error) {
	const op = "crypto.NewCachedKeySet"
	if src == nil {
		return nil, errs.NewConfigurationError(op, "a key source is required", nil)
	}
	if err := opts.Validate(); err != nil {
		return nil, errs.NewConfigurationError(op, err.Error(), err)
	}
	return &CachedKeySet{src: src, opts: opts.withDefaults()}, nil
}

// PublicKey implements [KeySet]. A kid the keys lack makes the set
// fetch them again, unless the last fetch was less than RefetchInterval
// ago. A kid they still lack is a refused token, with
// ErrorCodeJWTUnknownKey.
func (s *CachedKeySet) PublicKey(ctx context.Context, kid string) (PublishedKey, error) {
	const op = "CachedKeySet.PublicKey"
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx, false); err != nil {
		return PublishedKey{}, err
	}
	if key, ok := s.lookup(kid); ok {
		return key, nil
	}
	if err := s.refresh(ctx, true); err != nil {
		return PublishedKey{}, err
	}
	if key, ok := s.lookup(kid); ok {
		return key, nil
	}
	return PublishedKey{}, errs.NewJWTError(op, errs.CodeJWTUnknownKey, nil)
}

// PublicKeys implements [KeySet]. It returns a copy of the keys,
// fetched first when there are none yet or they are older than the TTL.
func (s *CachedKeySet) PublicKeys(ctx context.Context) ([]PublishedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx, false); err != nil {
		return nil, err
	}
	return slices.Clone(s.keys), nil
}

// lookup returns the first key with kid. A set may hold two keys of
// different types under one kid (RFC 7517, section 4.5); VerifyJWT looks
// for the other one in PublicKeys when the first does not fit the token.
func (s *CachedKeySet) lookup(kid string) (PublishedKey, bool) {
	for _, key := range s.keys {
		if key.KID == kid {
			return key, true
		}
	}
	return PublishedKey{}, false
}

// refresh fetches the keys when they are due: when there are none yet, when
// they are older than the TTL, or, with force, for a kid they lack. Fetches
// are at least RefetchInterval apart. It returns an error only when the
// source failed and no keys can be used: they are missing or older than TTL
// plus MaxStale, or, with force, the last fetch failed, and a kid the keys
// lack can't be told from a new one. s.mu is held.
func (s *CachedKeySet) refresh(ctx context.Context, force bool) error {
	now := s.opts.Now()
	fetched := !s.fetchedAt.IsZero()
	fresh := fetched && now.Sub(s.fetchedAt) < s.opts.TTL
	if fresh && !force {
		return nil
	}
	if !s.triedAt.IsZero() && now.Sub(s.triedAt) < s.opts.RefetchInterval {
		// Too soon to fetch again. After a fetch that worked, the keys
		// decide. After one that failed, stale keys are used for a lookup,
		// and a kid they lack gets the failure.
		if s.lastErr == nil || (!force && s.usableStale(now)) {
			return nil
		}
		return s.lastErr
	}
	keys, err := s.src.Keys(ctx)
	if err != nil {
		err = fmt.Errorf("key set: %w", err)
		if ctx.Err() == nil {
			// The source failed, and not the caller, whose context ended:
			// the next fetch waits for RefetchInterval.
			s.triedAt, s.lastErr = now, err
		}
		if !force && s.usableStale(now) {
			return nil
		}
		return err
	}
	s.keys, s.fetchedAt, s.triedAt, s.lastErr = keys, now, now, nil
	return nil
}

// usableStale reports whether keys past their TTL may still be used: there
// are some, and they are less than TTL plus MaxStale old.
func (s *CachedKeySet) usableStale(now time.Time) bool {
	return !s.fetchedAt.IsZero() && s.opts.MaxStale > 0 && now.Sub(s.fetchedAt) < s.opts.TTL+s.opts.MaxStale
}
