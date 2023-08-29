package cmd

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/takumakume/kev-to-dependencytrack/config"
	"github.com/takumakume/kev-to-dependencytrack/dependencytrack"
	"github.com/takumakume/kev-to-dependencytrack/kev"
)

var rootCmd = &cobra.Command{
	Use:   "kev-to-dependencytrack",
	Short: "",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c := config.New(
			viper.GetString("base-url"),
			viper.GetString("api-key"),
			viper.GetString("policy-name"),
			viper.GetString("policy-operator"),
			viper.GetString("policy-violation-state"),
			viper.GetStringSlice("policy-projects"),
			viper.GetStringSlice("policy-tags"),
		)
		if err := c.Validate(); err != nil {
			return err
		}

		k := kev.New()
		if err := k.Init(); err != nil {
			return err
		}

		cves := k.Catalog().VulnerabilitiyIDs()

		dtrackClient, err := dependencytrack.New(c.BaseURL, c.APIKey, 10*time.Second)
		if err != nil {
			return err
		}

		policy, err := dtrackClient.ApplyPolicy(ctx, c.PolicyName, c.PolicyOperator, c.PolicyViolationState, c.PolicyProjects, c.PolicyTags, cves)
		if err != nil {
			return err
		}

		log.Printf("PolicyConditions count: %d", len(policy.PolicyConditions))

		return nil
	},
}

func init() {
	flags := rootCmd.PersistentFlags()
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("DT")

	flags.StringP("base-url", "u", "http://127.0.0.1:8081/", "Dependency Track base URL (env: DT_BASE_URL)")
	flags.StringP("api-key", "k", "", "Dependency Track API key (env: DT_API_KEY)")
	flags.StringP("policy-name", "", "", "Dependency Track policy name")
	flags.StringP("policy-operator", "", "ANY", "Dependency Track policy operator")
	flags.StringP("policy-violation-state", "", "WARN", "Dependency Track policy violationState")
	flags.StringSliceP("policy-projects", "", []string{}, "Dependency Track policy projects")
	flags.StringSliceP("policy-tags", "", []string{}, "Dependency Track policy tags")

	viper.BindPFlag("base-url", flags.Lookup("base-url"))
	viper.BindPFlag("api-key", flags.Lookup("api-key"))
	viper.BindPFlag("policy-name", flags.Lookup("policy-name"))
	viper.BindPFlag("policy-operator", flags.Lookup("policy-operator"))
	viper.BindPFlag("policy-violation-state", flags.Lookup("policy-violation-state"))
	viper.BindPFlag("policy-projects", flags.Lookup("policy-projects"))
	viper.BindPFlag("policy-tags", flags.Lookup("policy-tags"))
}

func Execute() error {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)

	return rootCmd.Execute()
}
