package session

import (
	"log"

	"ssrok/internal/utils"
)

const (
	EnvRedisHost     = "REDIS_HOST"
	EnvRedisPort     = "REDIS_PORT"
	EnvRedisUser     = "REDIS_USERNAME"
	EnvRedisPassword = "REDIS_PASSWORD"
)

func NewStore() (StoreInterface, error) {
	redisHost := utils.GetEnv(EnvRedisHost, "")

	if redisHost != "" {
		redisPort := utils.GetEnv(EnvRedisPort, "6379")
		redisUser := utils.GetEnv(EnvRedisUser, "")
		redisPassword := utils.GetEnv(EnvRedisPassword, "")

		store, err := NewRedisStore(redisHost, redisPort, redisUser, redisPassword)
		if err != nil {
			log.Printf("⚠️  Redis connection failed: %v", err)
			log.Println("💾 Falling back to in-memory session store")
			return NewMemoryStore(), nil
		}
		log.Printf("💾 Using Redis session store: %s:%s", redisHost, redisPort)
		return store, nil
	}

	log.Println("💾 Using in-memory session store")
	return NewMemoryStore(), nil
}
