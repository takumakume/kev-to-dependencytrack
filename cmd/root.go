package cmd

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
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

		dtrackClient, err := dependencytrack.New(c.BaseURL, c.APIKey, 10*time.Second)
		if err != nil {
			return err
		}

		return run(ctx, dtrackClient, c, k.Catalog().VulnerabilitiyIDs())
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

func run(ctx context.Context, client dependencytrack.DependencyTrackClient, config *config.Config, cves []string) error {
	desierdPolicy := desierdPolicy(config.PolicyName, config.PolicyOperator, config.PolicyViolationState)
	policy, err := applyPolicy(ctx, client, desierdPolicy)
	if err != nil {
		return err
	}

	tags := desierdTags(config.PolicyTags)
	if err := applyTags(ctx, client, policy, tags); err != nil {
		return err
	}

	projectUUIDs, err := desierdProjectUUIDs(ctx, client, config.PolicyProjects)
	if err != nil {
		return err
	}
	if err := applyProjects(ctx, client, policy, projectUUIDs); err != nil {
		return err
	}

	desierdPolicyConditions := desierdPolicyConditions(cves)
	if err := applyPolicyConditions(ctx, client, policy, desierdPolicyConditions); err != nil {
		return err
	}

	return nil
}

func applyPolicy(ctx context.Context, client dependencytrack.DependencyTrackClient, desierdPolicy dtrack.Policy) (policy dtrack.Policy, err error) {
	if policy, err = client.GetPolicyForName(ctx, desierdPolicy.Name); err != nil {
		if dependencytrack.IsNotFound(err) {
			log.Printf("apply policy: create policy: %s", desierdPolicy.Name)

			policy, err = client.CreatePolicy(ctx, desierdPolicy)
			if err != nil {
				return policy, err
			}
			// FIXME: https://github.com/DependencyTrack/dependency-track/issues/2365
			policy.Operator = dtrack.PolicyOperator(desierdPolicy.Operator)
			policy.ViolationState = dtrack.PolicyViolationState(desierdPolicy.ViolationState)
			policy, err = client.UpdatePolicy(ctx, policy)
			if err != nil {
				return policy, err
			}
		} else {
			return policy, err
		}

	} else {
		if client.NeedsUpdatePolicy(policy, desierdPolicy) {
			log.Printf("apply policy: update policy: %s", desierdPolicy.Name)

			policy.Operator = desierdPolicy.Operator
			policy.ViolationState = desierdPolicy.ViolationState
			policy, err = client.UpdatePolicy(ctx, policy)
			if err != nil {
				return policy, err
			}
		}
	}

	return policy, err
}

func applyTags(ctx context.Context, client dependencytrack.DependencyTrackClient, policy dtrack.Policy, tags []dtrack.Tag) error {
	remove, add := compareTags(policy.Tags, tags)
	for _, o := range remove {
		log.Printf("apply tags: remove tag %v", o)

		_, err := client.DeleteTag(ctx, policy.UUID, o.Name)
		if err != nil {
			if dependencytrack.IsNotFound(err) {
				log.Printf("WARN: apply tags: remove tag: not found %v", o)

				continue
			}
			return err
		}
	}
	for _, o := range add {
		log.Printf("apply tags: add tag %v", o)

		_, err := client.AddTag(ctx, policy.UUID, o.Name)
		if err != nil {
			if dependencytrack.IsNotFound(err) {
				log.Printf("WARN: apply tags: add tag: not found %v", o)

				continue
			}
			return err
		}
	}
	return nil
}

func applyProjects(ctx context.Context, client dependencytrack.DependencyTrackClient, policy dtrack.Policy, projectUUIDs []uuid.UUID) error {
	currentProjectUUIDs := []uuid.UUID{}
	for _, p := range policy.Projects {
		currentProjectUUIDs = append(currentProjectUUIDs, p.UUID)
	}

	remove, add := compareUUIDs(currentProjectUUIDs, projectUUIDs)
	for _, o := range remove {
		log.Printf("apply projects: remove project %s", o)

		_, err := client.DeleteProject(ctx, policy.UUID, o)
		if err != nil {
			return err
		}
	}
	for _, o := range add {
		log.Printf("apply projects: add project %s", o)

		_, err := client.AddProject(ctx, policy.UUID, o)
		if err != nil {
			return err
		}
	}
	return nil
}

func applyPolicyConditions(ctx context.Context, client dependencytrack.DependencyTrackClient, policy dtrack.Policy, conditions []dtrack.PolicyCondition) error {
	remove, add := comparePolicyConditions(policy.PolicyConditions, conditions)
	for _, o := range remove {
		log.Printf("apply policyConditions: remove policyCondition %s", o.Value)

		if err := client.DeletePolicyCondition(ctx, o.UUID); err != nil {
			return err
		}
	}
	for _, o := range add {
		log.Printf("apply policyConditions: add policyCondition %s", o.Value)

		_, err := client.CreatePolicyCondition(ctx, policy.UUID, o)
		if err != nil {
			return err
		}
	}
	return nil
}

func desierdPolicy(policyName, operator, violationState string) dtrack.Policy {
	return dtrack.Policy{
		Name:           policyName,
		Operator:       dtrack.PolicyOperator(operator),
		ViolationState: dtrack.PolicyViolationState(violationState),
	}
}

func desierdTags(tagSlice []string) []dtrack.Tag {
	m := make(map[string]bool)
	uniq := []string{}

	for _, ele := range tagSlice {
		if !m[ele] {
			m[ele] = true
			uniq = append(uniq, ele)
		}
	}

	tags := make([]dtrack.Tag, len(uniq))
	for i, s := range uniq {
		tags[i] = dtrack.Tag{Name: s}
	}

	return tags
}

func desierdProjectUUIDs(ctx context.Context, client dependencytrack.DependencyTrackClient, projectNameVersions []string) (uuids []uuid.UUID, err error) {
	projects := []dtrack.Project{}
	for _, nv := range projectNameVersions {
		projectNameVersion := strings.SplitN(nv, ":", 2)
		if len(projectNameVersion) == 2 {
			p, err := client.GetProjectForNameVersion(ctx, projectNameVersion[0], projectNameVersion[1], true, true)
			if err != nil {
				if dependencytrack.IsNotFound(err) {
					log.Printf("WARN: desierdProjectUUIDs: GetProjectForNameVersion: project version not found %q", nv)

					continue
				}
				return uuids, err
			}
			projects = append(projects, p)
		} else {
			pp, err := client.GetProjectsForName(ctx, projectNameVersion[0], true, true)
			if err != nil {
				if dependencytrack.IsNotFound(err) {
					log.Printf("WARN: desierdProjectUUIDs: GetProjectsForName: project not found %q", nv)

					continue
				}
				return uuids, err
			}
			projects = append(projects, pp...)
		}
	}

	seen := make(map[uuid.UUID]bool)
	for _, project := range projects {
		if _, ok := seen[project.UUID]; ok {
			continue
		}
		seen[project.UUID] = true
		uuids = append(uuids, project.UUID)
	}

	return uuids, nil
}

func desierdPolicyConditions(cves []string) (conds []dtrack.PolicyCondition) {
	m := make(map[string]bool)
	uniq := []string{}

	for _, ele := range cves {
		if !m[ele] {
			m[ele] = true
			uniq = append(uniq, ele)
		}
	}

	for _, c := range uniq {
		conds = append(conds, dtrack.PolicyCondition{
			Subject:  dtrack.PolicyConditionSubjectVulnerabilityID,
			Operator: dtrack.PolicyConditionOperatorIs,
			Value:    c,
		})
	}
	return conds
}

func compareTags(aa, bb []dtrack.Tag) (remove, add []dtrack.Tag) {
	aaMap := make(map[string]dtrack.Tag)
	for _, a := range aa {
		aaMap[a.Name] = a
	}

	for _, b := range bb {
		_, ok := aaMap[b.Name]
		if ok {
			delete(aaMap, b.Name)
			continue
		}
		add = append(add, b)
	}

	for _, a := range aaMap {
		remove = append(remove, a)
	}

	return remove, add
}

func compareUUIDs(aa, bb []uuid.UUID) (remove, add []uuid.UUID) {
	aaMap := make(map[uuid.UUID]uuid.UUID)
	for _, a := range aa {
		aaMap[a] = a
	}

	for _, b := range bb {
		_, ok := aaMap[b]
		if ok {
			delete(aaMap, b)
			continue
		}
		add = append(add, b)
	}

	for _, a := range aaMap {
		remove = append(remove, a)
	}

	return remove, add
}

func comparePolicyConditions(aa, bb []dtrack.PolicyCondition) (removed, added []dtrack.PolicyCondition) {
	aaMap := make(map[string]dtrack.PolicyCondition)
	for _, a := range aa {
		aaMap[a.Value] = a
	}

	for _, b := range bb {
		_, ok := aaMap[b.Value]
		if ok {
			delete(aaMap, b.Value)
			continue
		}
		added = append(added, b)
	}

	for _, a := range aaMap {
		removed = append(removed, a)
	}

	return removed, added
}
