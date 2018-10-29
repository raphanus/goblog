package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	migrate "github.com/rubenv/sql-migrate"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	//"github.com/raphanus/goblog/internal/api"
	//"github.com/raphanus/goblog/internal/api/auth"
	"github.com/raphanus/goblog/internal/config"
	//"github.com/raphanus/goblog/internal/handler/mqtthandler"
	//"github.com/raphanus/goblog/internal/handler/multihandler"
	//"github.com/raphanus/goblog/internal/migrations"
	"github.com/raphanus/goblog/internal/storage"
)

func run(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tasks := []func() error{
		setLogLevel,
		printStartMessage,
		setPostgreSQLConnection,
		setRedisPool,
		setHandler,
		setNetworkServerClient,
		runDatabaseMigrations,
		setJWTSecret,
		setHashIterations,
		setDisableAssignExistingUsers,
		startGoBlogServerAPI,
	}

	for _, t := range tasks {
		if err := t(); err != nil {
			log.Fatal(err)
		}
	}

	sigChan := make(chan os.Signal)
	exitChan := make(chan struct{})
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	log.WithField("signal", <-sigChan).Info("signal received")
	go func() {
		log.Warning("stopping lora-app-server")
		// todo: handle graceful shutdown?
		exitChan <- struct{}{}
	}()
	select {
	case <-exitChan:
	case s := <-sigChan:
		log.WithField("signal", s).Info("signal received, stopping immediately")
	}

	return nil
}

func setLogLevel() error {
	log.SetLevel(log.Level(uint8(config.C.General.LogLevel)))
	return nil
}

func printStartMessage() error {
	log.WithFields(log.Fields{
		"version": version,
		"docs":    "https://www.raphanus.club/",
	}).Info("starting GO Blog Server")
	return nil
}

func setPostgreSQLConnection() error {
	log.Info("connecting to postgresql")
	db, err := storage.OpenDatabase(config.C.PostgreSQL.DSN)
	if err != nil {
		return errors.Wrap(err, "database connection error")
	}
	config.C.PostgreSQL.DB = db
	return nil
}

func setRedisPool() error {
	// setup redis pool
	log.Info("setup redis connection pool")
	config.C.Redis.Pool = storage.NewRedisPool(config.C.Redis.URL)
	return nil
}

func setHandler() error {
	h, err := mqtthandler.NewHandler(
		config.C.Redis.Pool,
		config.C.ApplicationServer.Integration.MQTT,
	)
	if err != nil {
		return errors.Wrap(err, "setup mqtt handler error")
	}
	config.C.ApplicationServer.Integration.Handler = multihandler.NewHandler(h)
	return nil
}

func runDatabaseMigrations() error {
	if config.C.PostgreSQL.Automigrate {
		log.Info("applying database migrations")
		m := &migrate.AssetMigrationSource{
			Asset:    migrations.Asset,
			AssetDir: migrations.AssetDir,
			Dir:      "",
		}
		n, err := migrate.Exec(config.C.PostgreSQL.DB.DB.DB, "postgres", m, migrate.Up)
		if err != nil {
			return errors.Wrap(err, "applying migrations error")
		}
		log.WithField("count", n).Info("migrations applied")
	}

	return nil
}

func setJWTSecret() error {
	storage.SetUserSecret(config.C.GoBlogServer.API.JWTSecret)
	return nil
}

func setHashIterations() error {
	storage.HashIterations = config.C.General.PasswordHashIterations
	return nil
}

func setDisableAssignExistingUsers() error {
	auth.DisableAssignExistingUsers = config.C.GoBlogServer.API.DisableAssignExistingUsers
	return nil
}

func startGoBlogServerAPI() error {
	log.WithFields(log.Fields{
		"bind":     config.C.GoBlogServer.Bind,
		"ca_cert":  config.C.GoBlogServer.CACert,
		"tls_cert": config.C.GoBlogServer.TLSCert,
		"tls_key":  config.C.GoBlogServer.TLSKey,
	}).Info("starting join-server api")

	server := http.Server{
		Handler: api.NewJoinServerAPI(),
		Addr:    config.C.GoBlogServer.Bind,
	}

	if config.C.GoBlogServer.CACert == "" || config.C.GoBlogServer.TLSCert == "" || config.C.GoBlogServer.TLSKey == "" {
		go func() {
			err := server.ListenAndServe()
			log.WithError(err).Error("join-server api error")
		}()
		return nil
	}

	caCert, err := ioutil.ReadFile(config.C.GoBlogServer.CACert)
	if err != nil {
		return errors.Wrap(err, "read ca certificate error")
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return errors.New("append ca certificate error")
	}

	server.TLSConfig = &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	go func() {
		err := server.ListenAndServeTLS(config.C.GoBlogServer.TLSCert, config.C.GoBlogServer.TLSKey)
		log.WithError(err).Error("join-server api error")
	}()

	return nil
}
