package cmd

import (
	"strings"

	"github.com/konveyor/auth-server/internal/api"
	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "auth-server",
		Short: "An authentication and authorization server which provides an OIDC API.",
		Long:  "An authentication and authorization server which provides an OIDC API.",
		Args:  cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			if err := api.Serve(); err != nil {
				logrus.Fatal(err)
			}
		},
	}
	app := types.APP_NAME_SHORT
	rootCmd.PersistentFlags().StringP("config", "c", "", "Path to the config file.")
	rootCmd.PersistentFlags().String("log-level", logrus.InfoLevel.String(), `Set the logging level. Options are: ["panic", "fatal", "error", "warn", "info", "debug", "trace"]`)
	rootCmd.Flags().Bool("clean-startup", false, "Delete the data directory if it exists on startup.")
	rootCmd.Flags().Bool("secure-cookies", false, "Send cookies only if it is a https TLS connection. Turn this on in production environments.")
	rootCmd.Flags().Bool("string-errors", false, "Send all error messages as strings instead of detailed error objects.")
	rootCmd.Flags().IntP("port", "p", 8080, "Port to listen on.")
	rootCmd.Flags().Int("max-login-attempts", 5, "Maximum number of login attempts before the account gets locked.")
	rootCmd.Flags().Int("cookie-max-age", 2*3600, "Max age for session cookies (in seconds).")
	rootCmd.Flags().Int("max-upload-size", 100*1024*1024, "Max size (in bytes) for file uploads.")
	rootCmd.Flags().Int("access-token-timeout", 10*60, "Timeout (in seconds) for access tokens. Default 10 minutes.")
	rootCmd.Flags().Int("refresh-token-timeout", 2*60*60, "Timeout (in seconds) for refresh tokens. Default 2 hours.")
	rootCmd.Flags().String("data-dir", "data", "Path to the directory where all the data will stored. It will be created if it doesn't exist.")
	rootCmd.Flags().String("static-files-dir", "", "Path to the directory containing static files to be served. Used to serve the auth server UI.")
	rootCmd.Flags().String("session-secret", "", "A random secret to use for signing session cookies. By default it generates a new session secret.")
	rootCmd.Flags().String("current-host", "http://localhost:8080", "URL where this server is deployed.")
	rootCmd.Flags().String("auth-server-base-path", "/auth-server", "If the authorization server is hosted under a sub path, specify it here.")
	rootCmd.Flags().String("auth-server-realm", "master-realm", "The realm configured in the authorization server.")
	rootCmd.Flags().String("auth-server-login-redirect-url", "", "URL where the auth server is available to complete the OIDC login flow.")
	rootCmd.Flags().String("auth-server-login-redirect-host", "", "URL where the auth server is available to the browser.")
	rootCmd.Flags().String(app+"-client-client-id", app+"-client", "The OAuth 2.0 client id for the client side.")
	rootCmd.Flags().String(app+"-client-client-secret", "af10bd64-03e6-47cc-8733-4d04354cf625", "The OAuth 2.0 client secret for the client side.")
	rootCmd.Flags().String(app+"-client-id-not-client-id", "fb0411ca-3637-4925-9325-9f979bb0e826", "The Id of the client on the Keycloak server. This is NOT the client Id used by OAuth 2.0.")
	rootCmd.Flags().String(app+"-server-client-id", app+"-server", "The OAuth 2.0 client id for the server side.")
	rootCmd.Flags().String(app+"-server-client-secret", "8a1340ff-de5d-42a0-8b40-b6239c7cfc58", "The OAuth 2.0 client secret for the server side.")
	rootCmd.Flags().String("default-resource-id", "b4d9b0fd-ffdb-4533-9536-5c315af07352", "Resource id on the Keycloak server.")
	rootCmd.Flags().String("https-cert", "", "The path to the certificate file for HTTPS.")
	rootCmd.Flags().String("https-key", "", "The path to the private key file for HTTPS. Must be an unencrypted private key file")
	// CloudEvents
	rootCmd.Flags().Bool("cloud-events-enabled", false, "Enable CloudEvents reporting.")
	rootCmd.Flags().String("cloud-events-endpoint", "", "Endpoint where CloudEvents are reported.")
	rootCmd.Flags().String("cloud-events-access-token", "", "Access token to use when reporting CloudEvents.")
	rootCmd.Flags().String("cloud-events-spec-version", "1.0", "Version of the CloudEvents spec.")
	rootCmd.Flags().String("cloud-events-type", "", "Type of the CloudEvents event.")
	rootCmd.Flags().String("cloud-events-subject", "auth-server-api", "Subject to use when reporting CloudEvents.")

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.BindPFlags(rootCmd.Flags())
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	return rootCmd
}

func readConfigFile() {
	viper.SetConfigType("yaml")
	if !viper.IsSet("config") {
		return
	}
	configFilePath := viper.GetString("config")
	logrus.Infof("reading config from file at path %s", configFilePath)
	viper.SetConfigFile(configFilePath)
	if err := viper.ReadInConfig(); err != nil {
		logrus.Fatalf("failed to read the config file at path %s . Error: %q", configFilePath, err)
	}
}

func setupViper() {
	viper.SetEnvPrefix(strings.ToUpper(types.APP_NAME_SHORT))
	viper.AutomaticEnv()
	readConfigFile()
	if err := viper.Unmarshal(&common.Config); err != nil {
		logrus.Fatalf("failed to unmarshal the config. Error: %q", err)
	}
}

func onInitialize() {
	setupViper()
	logLevel, err := logrus.ParseLevel(common.Config.LogLevel)
	if err != nil {
		logrus.Fatalf("the log level is invalid. Error: %q", err)
	}
	if common.Config.MaxLoginAttempts <= 0 {
		logrus.Fatalf("the maximum number of login attempts must be a positive integer")
	}
	logrus.SetLevel(logLevel)
	logrus.Debugf("log level: %s", logLevel.String())
	logrus.Debugf("using the following configuration:\n%s", common.Config.String())
}

// SetupCobraAndRun is the setup and cobra function
func SetupCobraAndRun() error {
	rootCmd := getRootCommand()
	rootCmd.AddCommand(getVersionCommand())
	cobra.OnInitialize(onInitialize)
	return rootCmd.Execute()
}
