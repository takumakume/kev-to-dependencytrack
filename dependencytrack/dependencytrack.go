package dependencytrack

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
)

type DependencyTrackClient interface {
}

type DependencyTrack struct {
	Client *dtrack.Client
}

func New(baseURL, apiKey string, timeout time.Duration) (*DependencyTrack, error) {
	client, err := dtrack.NewClient(baseURL, dtrack.WithAPIKey(apiKey), dtrack.WithTimeout(timeout), dtrack.WithDebug(false))
	if err != nil {
		return nil, err
	}

	return &DependencyTrack{
		Client: client,
	}, nil
}

func (d *DependencyTrack) ApplyPolicy(ctx context.Context, name, operator, violationState string, projectNameVersions, tags, cves []string) (dtrack.Policy, error) {
	var policy dtrack.Policy

	log.Printf("Creating or updating policy %q operator:%s, violationState: %s projectNameVersions:%v, tags:%v", name, operator, violationState, projectNameVersions, tags)

	if err := validatePolicyOperator(dtrack.PolicyOperator(operator)); err != nil {
		return policy, err
	}
	if err := validatePolicyViolationState(dtrack.PolicyViolationState(violationState)); err != nil {
		return policy, err
	}

	policies, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.Policy], error) {
		return d.Client.Policy.GetAll(ctx, po)
	})
	if err != nil {
		return policy, err
	}

	for _, p := range policies {
		if p.Name == name {
			policy = p
			break
		}
	}

	if policy.Name == "" {
		newPolicy := dtrack.Policy{
			Name:           name,
			Operator:       dtrack.PolicyOperator(operator),
			ViolationState: dtrack.PolicyViolationState(violationState),
		}

		log.Printf("Creating policy: %+v", newPolicy)
		policy, err = d.Client.Policy.Create(ctx, newPolicy)
		if err != nil {
			return policy, err
		}

		// FIXME: https://github.com/DependencyTrack/dependency-track/issues/2365
		policy.ViolationState = newPolicy.ViolationState
		policy.Operator = newPolicy.Operator
		policy, err = d.Client.Policy.Update(ctx, policy)
		if err != nil {
			return policy, err
		}
	} else {
		switch {
		case policy.Operator != dtrack.PolicyOperator(operator):
		case policy.ViolationState != dtrack.PolicyViolationState(violationState):
			policy.Operator = dtrack.PolicyOperator(operator)
			policy.ViolationState = dtrack.PolicyViolationState(violationState)

			log.Printf("Updating policy %q %+v", name, policy)
			policy, err = d.Client.Policy.Update(ctx, policy)
			if err != nil {
				return policy, err
			}
		}
	}

	policyUUID := policy.UUID

	if len(tags) > 0 {
		remove, add := compareSlice(tagToSlice(policy.Tags), tags)
		if len(remove) > 0 {
			log.Printf("Removing tags %q from policy %q", remove, policy.Name)
			for _, r := range remove {
				if _, err := d.Client.Policy.DeleteTag(ctx, policyUUID, r); err != nil {
					log.Printf("WARN: failed to remove tag %q from policy %q: %s", r, policy.Name, err)
					continue
				}
				log.Printf("Removed tag %q from policy %q", r, policy.Name)
			}
		}
		if len(add) > 0 {
			log.Printf("Adding tags %q to policy %q", add, policy.Name)
			for _, a := range add {
				if _, err := d.Client.Policy.AddTag(ctx, policyUUID, a); err != nil {
					log.Printf("WARN: failed to add tag %q from policy %q: %s", a, policy.Name, err)
					continue
				}
				log.Printf("Added tag %q to policy %q", a, policy.Name)
			}
		}
	}

	if len(projectNameVersions) > 0 {
		desieredProjects := []dtrack.Project{}
		for _, nv := range projectNameVersions {
			projectNameVersion := strings.SplitN(nv, ":", 2)
			if len(projectNameVersion) == 0 {
				return policy, fmt.Errorf("invalid project name version: %q", nv)
			}

			projectName := projectNameVersion[0]

			pp, err := d.Client.Project.GetProjectsForName(ctx, projectName, true, true)
			if err != nil {
				log.Printf("WARN: failed to get project %q: %s", projectName, err)
				continue
			}
			for _, p := range pp {
				if len(projectNameVersion) == 2 {
					if p.Version == projectNameVersion[1] {
						desieredProjects = append(desieredProjects, p)
					}
				} else {
					desieredProjects = append(desieredProjects, p)
				}
			}

		}

		currentProjectUUIDs := projectsToProjectUUIDs(policy.Projects)
		desieredProjectUUIDs := projectsToProjectUUIDs(desieredProjects)

		remove, add := compareUUID(currentProjectUUIDs, desieredProjectUUIDs)
		if len(remove) > 0 {
			log.Printf("Removing projects %q from policy %q", remove, policy.Name)

			for _, r := range remove {
				if _, err := d.Client.Policy.DeleteProject(ctx, policyUUID, r); err != nil {
					return policy, err
				}

				log.Printf("Removed project %q from policy %q", r, policy.Name)
			}
		}

		if len(add) > 0 {
			log.Printf("Adding projects %q to policy %q", add, policy.Name)

			for _, a := range add {
				if _, err := d.Client.Policy.AddProject(ctx, policyUUID, a); err != nil {
					return policy, err
				}

				log.Printf("Added project %q to policy %q", a, policy.Name)
			}
		}
	}

	if len(cves) > 0 {
		desieredConditions := []dtrack.PolicyCondition{}
		for _, cve := range cves {
			cond := dtrack.PolicyCondition{
				Subject:  dtrack.PolicyConditionSubjectVulnerabilityID,
				Operator: dtrack.PolicyConditionOperatorIs,
				Value:    cve,
			}
			desieredConditions = append(desieredConditions, cond)
		}

		currentConditions := policy.PolicyConditions

		remove, add := comparePolicyConditions(currentConditions, desieredConditions)
		if len(remove) > 0 {
			log.Printf("Removing conditions from policy %q", policy.Name)
			for _, r := range remove {
				log.Printf("Removing condition %q from policy %q", r.UUID, policy.Name)
				if err := d.Client.PolicyCondition.Delete(ctx, r.UUID); err != nil {
					return policy, err
				}

				log.Printf("Removed condition %q from policy %q", r.Value, policy.Name)
			}
		}

		if len(add) > 0 {
			log.Printf("Adding conditions from policy %q", policy.Name)
			for _, a := range add {
				_, err = d.Client.PolicyCondition.Create(ctx, policyUUID, a)
				if err != nil {
					return policy, err
				}
				log.Printf("Added condition %q from policy %q", a.Value, policy.Name)
			}
		}

	}

	policy, err = d.Client.Policy.Get(ctx, policyUUID)
	if err != nil {
		return policy, err
	}

	return policy, nil
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

func validatePolicyOperator(operator dtrack.PolicyOperator) error {
	switch operator {
	case dtrack.PolicyOperatorAny,
		dtrack.PolicyOperatorAll:
		return nil
	default:
		return fmt.Errorf("invalid PolicyOperator: %q", operator)
	}
}

func validatePolicyViolationState(violationState dtrack.PolicyViolationState) error {
	switch violationState {
	case dtrack.PolicyViolationStateInfo,
		dtrack.PolicyViolationStateWarn,
		dtrack.PolicyViolationStateFail:
		return nil
	default:
		return fmt.Errorf("invalid PolicyViolationState: %q", violationState)
	}
}

func tagToSlice(tags []dtrack.Tag) []string {
	slice := make([]string, len(tags))
	for i, t := range tags {
		slice[i] = t.Name
	}
	return slice
}

func compareSlice(a, b []string) (removed, added []string) {
	aMap := make(map[string]bool)
	for _, element := range a {
		aMap[element] = true
	}

	for _, element := range b {
		if _, ok := aMap[element]; ok {
			delete(aMap, element)
		} else {
			added = append(added, element)
		}
	}

	for element := range aMap {
		removed = append(removed, element)
	}

	return removed, added
}

func conditionsToValue(conds []dtrack.PolicyCondition) []string {
	slice := make([]string, len(conds))
	for i, cond := range conds {
		slice[i] = cond.Value
	}
	return slice
}

func projectsToProjectUUIDs(projects []dtrack.Project) []uuid.UUID {
	projectUUIDs := make([]uuid.UUID, len(projects))
	for i, p := range projects {
		projectUUIDs[i] = p.UUID
	}
	return projectUUIDs
}

func compareUUID(a, b []uuid.UUID) (removed, added []uuid.UUID) {
	aMap := make(map[uuid.UUID]bool)
	for _, element := range a {
		aMap[element] = true
	}

	for _, element := range b {
		if _, ok := aMap[element]; ok {
			delete(aMap, element)
		} else {
			added = append(added, element)
		}
	}

	for element := range aMap {
		removed = append(removed, element)
	}

	return removed, added
}
