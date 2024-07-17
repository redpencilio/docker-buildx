package main

import (
	"context"
	"os"

	"codeberg.org/woodpecker-plugins/plugin-docker-buildx/plugin"
	"github.com/joho/godotenv"
	"github.com/urfave/cli/v3"

	"codeberg.org/woodpecker-plugins/drone-plugin-lib/errors"
	"codeberg.org/woodpecker-plugins/drone-plugin-lib/urfave"
)

var version = "unknown"

func main() {
	settings := &plugin.Settings{
		CustomCertStore: "/etc/docker/certs.d/",
	}

	if _, err := os.Stat("/run/drone/env"); err == nil {
		godotenv.Overload("/run/drone/env")
	}

	if envFile, set := os.LookupEnv("PLUGIN_ENV_FILE"); set {
		godotenv.Overload(envFile)
	}

	ctx := context.Background()

	app := &cli.Command{
		Name:    "docker-buildx",
		Usage:   "build docker container with DinD and buildx",
		Version: version,
		Flags:   append(settingsFlags(settings), urfave.Flags()...),
		Action:  run(settings),
	}

	if err := app.Run(ctx, os.Args); err != nil {
		errors.HandleExit(err)
	}
}

func run(settings *plugin.Settings) cli.ActionFunc {
	return func(ctx context.Context, c *cli.Command) error {
		urfave.LoggingFromContext(c)

		plugin := plugin.New(
			*settings,
			urfave.PipelineFromContext(c),
			urfave.NetworkFromContext(c),
		)

		if err := plugin.Validate(); err != nil {
			if e, ok := err.(errors.ExitCoder); ok {
				return e
			}

			return errors.ExitMessagef("validation failed: %w", err)
		}

		if err := plugin.Execute(); err != nil {
			if e, ok := err.(errors.ExitCoder); ok {
				return e
			}

			return errors.ExitMessagef("execution failed: %w", err)
		}

		return nil
	}
}
