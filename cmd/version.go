package cmd

import (
	"fmt"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/common/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getVersionCommand() *cobra.Command {
	// versionCmd represents the version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Long:  "Print the version information",
		Run:   func(*cobra.Command, []string) { fmt.Println(version.GetVersion(common.Config.VersionLong)) },
	}
	versionCmd.Flags().BoolP("long", "l", false, "print the version details")
	viper.BindPFlag("version-long", versionCmd.Flags().Lookup("long"))
	return versionCmd
}
