package config

import (
	"github.com/garyburd/redigo/redis"

	"github.com/raphanus/goblog/internal/common"
	//"github.com/raphanus/goblog/internal/handler"
	//"github.com/raphanus/goblog/internal/handler/mqtthandler"
)

// Config defines the configuration structure.
type Config struct {
	General struct {
		LogLevel               int `mapstructure:"log_level"`
		PasswordHashIterations int `mapstructure:"password_hash_iterations"`
	}

	PostgreSQL struct {
		DSN         string `mapstructure:"dsn"`
		Automigrate bool
		DB          *common.DBLogger `mapstructure:"db"`
	} `mapstructure:"postgresql"`

	Redis struct {
		URL  string `mapstructure:"url"`
		Pool *redis.Pool
	}

	GoBlogServer struct {
		ID string `mapstructure:"id"`

		Integration struct {
			//Handler handler.Handler
			//MQTT    mqtthandler.Config `mapstructure:"mqtt"`
		}

		API struct {
			Bind                       string
			TLSCert                    string `mapstructure:"tls_cert"`
			TLSKey                     string `mapstructure:"tls_key"`
			JWTSecret                  string `mapstructure:"jwt_secret"`
			DisableAssignExistingUsers bool   `mapstructure:"disable_assign_existing_users"`
		} `mapstructure:"api"`

		Branding struct {
			Header       string
			Footer       string
			Registration string
		}
	} `mapstructure:"go_blog_server"`
}

// C holds the global configuration.
var C Config
