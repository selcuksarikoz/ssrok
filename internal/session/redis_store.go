package session

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"ssrok/internal/constants"
)

type RedisStore struct {
	client   *redis.Client
	onExpire func(uuid string)
	ctx      context.Context
	cancel   func()
	wg       sync.WaitGroup
}

func NewRedisStore(host, port, username, password string) (*RedisStore, error) {
	opts := &redis.Options{
		Addr:     host + ":" + port,
		Username: username,
		Password: password,
		DB:       0,
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithCancel(context.Background())

	store := &RedisStore{
		client: client,
		ctx:    ctx,
		cancel: cancel,
	}

	if err := store.client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	store.startCleanup()

	return store, nil
}

func (st *RedisStore) OnExpire(fn func(uuid string)) {
	st.onExpire = fn
}

func (st *RedisStore) Save(session *Session) {
	data := SessionData{
		ID:           session.ID,
		UUID:         session.UUID,
		Port:         session.Port,
		PasswordHash: session.PasswordHash,
		TokenHash:    session.TokenHash,
		RateLimit:    session.RateLimit,
		UseTLS:       session.UseTLS,
		E2EE:         session.E2EE,
		CreatedAt:    session.CreatedAt,
		ExpiresAt:    session.ExpiresAt,
		TunnelActive: session.TunnelActive,
		RequestCount: session.RequestCount,
		LastRequest:  session.LastRequest,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal session: %v", err)
		return
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return
	}

	key := constants.RedisKeyPrefix + session.UUID
	if err := st.client.Set(st.ctx, key, jsonData, ttl).Err(); err != nil {
		log.Printf("Failed to save session to Redis: %v", err)
	} else {
		log.Printf("💾 Saving session to Redis: %s (TTL: %v)", session.UUID, ttl)
	}
}

func (st *RedisStore) Get(uuid string) (*Session, bool) {
	key := constants.RedisKeyPrefix + uuid

	data, err := st.client.Get(st.ctx, key).Result()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		log.Printf("Failed to get session from Redis: %v", err)
		return nil, false
	}

	log.Printf("🔍 Got session from Redis: %s", uuid)

	var sd SessionData
	if err := json.Unmarshal([]byte(data), &sd); err != nil {
		log.Printf("Failed to unmarshal session: %v", err)
		return nil, false
	}

	session := &Session{
		ID:           sd.ID,
		UUID:         sd.UUID,
		Port:         sd.Port,
		PasswordHash: sd.PasswordHash,
		TokenHash:    sd.TokenHash,
		RateLimit:    sd.RateLimit,
		UseTLS:       sd.UseTLS,
		E2EE:         sd.E2EE,
		CreatedAt:    sd.CreatedAt,
		ExpiresAt:    sd.ExpiresAt,
		TunnelActive: sd.TunnelActive,
		RequestCount: sd.RequestCount,
		LastRequest:  sd.LastRequest,
	}

	if session.RequestCount == nil {
		session.RequestCount = make(map[string]int)
	}
	if session.LastRequest == nil {
		session.LastRequest = make(map[string]time.Time)
	}

	if session.IsExpired() {
		st.Delete(uuid)
		if st.onExpire != nil {
			st.onExpire(uuid)
		}
		return nil, false
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl > 0 {
		st.client.Expire(st.ctx, key, ttl)
	}

	return session, true
}

func (st *RedisStore) Delete(uuid string) {
	key := constants.RedisKeyPrefix + uuid
	if err := st.client.Del(st.ctx, key).Err(); err != nil {
		log.Printf("Failed to delete session from Redis: %v", err)
	}
}

func (st *RedisStore) Close() error {
	st.cancel()
	st.wg.Wait()
	return st.client.Close()
}

func (st *RedisStore) startCleanup() {
	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		ticker := time.NewTicker(constants.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-st.ctx.Done():
				return
			case <-ticker.C:
				st.cleanupExpired()
			}
		}
	}()
}

func (st *RedisStore) cleanupExpired() {
	pattern := constants.RedisKeyPrefix + "*"
	iter := st.client.Scan(st.ctx, 0, pattern, 100).Iterator()

	for iter.Next(st.ctx) {
		key := iter.Val()
		uuid := key[len(constants.RedisKeyPrefix):]

		ttl, err := st.client.TTL(st.ctx, key).Result()
		if err != nil {
			continue
		}

		if ttl <= 0 {
			st.Delete(uuid)
			if st.onExpire != nil {
				st.onExpire(uuid)
			}
			log.Printf("🗑 Expired session cleaned up (Redis): %s", uuid)
		}
	}

	if err := iter.Err(); err != nil {
		log.Printf("Redis scan error: %v", err)
	}
}
