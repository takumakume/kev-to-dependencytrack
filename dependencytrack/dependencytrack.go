package dependencytrack

import (
	"context"
	"errors"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
)

type DependencyTrackClient interface {
	GetPolicyForName(ctx context.Context, policyName string) (p dtrack.Policy, err error)
	CreatePolicy(ctx context.Context, policy dtrack.Policy) (p dtrack.Policy, err error)
	UpdatePolicy(ctx context.Context, policy dtrack.Policy) (p dtrack.Policy, err error)
	NeedsUpdatePolicy(current, desierd dtrack.Policy) bool
	AddTag(ctx context.Context, policyUUID uuid.UUID, tagName string) (p dtrack.Policy, err error)
	DeleteTag(ctx context.Context, policyUUID uuid.UUID, tagName string) (p dtrack.Policy, err error)
	AddProject(ctx context.Context, policyUUID, projectUUID uuid.UUID) (p dtrack.Policy, err error)
	DeleteProject(ctx context.Context, policyUUID, projectUUID uuid.UUID) (p dtrack.Policy, err error)
	GetProjectsForName(ctx context.Context, projectName string, excludeInactive, onlyRoot bool) (pp []dtrack.Project, err error)
	GetProjectForNameVersion(ctx context.Context, projectName, projectVersion string, excludeInactive, onlyRoot bool) (p dtrack.Project, err error)
	CreatePolicyCondition(ctx context.Context, policyUUID uuid.UUID, policyCondition dtrack.PolicyCondition) (p dtrack.PolicyCondition, err error)
	DeletePolicyCondition(ctx context.Context, policyConditionUUID uuid.UUID) (err error)
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

var (
	ErrPolicyNotFound  = errors.New("policy not found")
	ErrProjectNotFound = errors.New("project not found")
)

func IsNotFound(err error) bool {
	switch err {
	case ErrPolicyNotFound, ErrProjectNotFound:
		return true
	}

	switch err := err.(type) {
	case *dtrack.APIError:
		if err.StatusCode == 404 {
			return true
		}
	}

	return false
}

func (d *DependencyTrack) GetPolicyForName(ctx context.Context, policyName string) (p dtrack.Policy, err error) {
	policies, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.Policy], error) {
		return d.Client.Policy.GetAll(ctx, po)
	})
	if err != nil {
		return p, err
	}

	for _, po := range policies {
		if po.Name == policyName {
			return po, nil
		}
	}
	return p, ErrPolicyNotFound
}

func (d *DependencyTrack) CreatePolicy(ctx context.Context, policy dtrack.Policy) (p dtrack.Policy, err error) {
	po, err := d.Client.Policy.Create(ctx, policy)
	if err != nil {
		return p, err
	}

	// FIXME: https://github.com/DependencyTrack/dependency-track/issues/2365
	po.ViolationState = policy.ViolationState
	po.Operator = policy.Operator
	p, err = d.UpdatePolicy(ctx, po)
	if err != nil {
		return p, err
	}

	return p, nil
}

func (d *DependencyTrack) UpdatePolicy(ctx context.Context, policy dtrack.Policy) (p dtrack.Policy, err error) {
	return d.Client.Policy.Update(ctx, policy)
}

func (d *DependencyTrack) NeedsUpdatePolicy(current, desierd dtrack.Policy) bool {
	switch {
	case current.Operator != desierd.Operator,
		current.ViolationState != desierd.ViolationState:
		return true
	}

	return false
}

func (d *DependencyTrack) AddTag(ctx context.Context, policyUUID uuid.UUID, tagName string) (p dtrack.Policy, err error) {
	return d.Client.Policy.AddTag(ctx, policyUUID, tagName)
}

func (d *DependencyTrack) DeleteTag(ctx context.Context, policyUUID uuid.UUID, tagName string) (p dtrack.Policy, err error) {
	return d.Client.Policy.DeleteTag(ctx, policyUUID, tagName)
}

func (d *DependencyTrack) AddProject(ctx context.Context, policyUUID, projectUUID uuid.UUID) (p dtrack.Policy, err error) {
	return d.Client.Policy.AddProject(ctx, policyUUID, projectUUID)
}

func (d *DependencyTrack) DeleteProject(ctx context.Context, policyUUID, projectUUID uuid.UUID) (p dtrack.Policy, err error) {
	return d.Client.Policy.DeleteProject(ctx, policyUUID, projectUUID)
}

func (d *DependencyTrack) GetProjectsForName(ctx context.Context, projectName string, excludeInactive, onlyRoot bool) (pp []dtrack.Project, err error) {
	pp, err = d.Client.Project.GetProjectsForName(ctx, projectName, excludeInactive, onlyRoot)
	if err != nil {
		return pp, err
	}
	if len(pp) == 0 {
		return pp, ErrProjectNotFound
	}
	return pp, nil
}

func (d *DependencyTrack) GetProjectForNameVersion(ctx context.Context, projectName, projectVersion string, excludeInactive, onlyRoot bool) (p dtrack.Project, err error) {
	projects, err := d.Client.Project.GetProjectsForName(ctx, projectName, excludeInactive, onlyRoot)
	if err != nil {
		return p, err
	}
	for _, project := range projects {
		if project.Version == projectVersion {
			return project, nil
		}
	}
	return p, ErrProjectNotFound
}

func (d *DependencyTrack) CreatePolicyCondition(ctx context.Context, policyUUID uuid.UUID, policyCondition dtrack.PolicyCondition) (p dtrack.PolicyCondition, err error) {
	return d.Client.PolicyCondition.Create(ctx, policyUUID, policyCondition)
}

func (d *DependencyTrack) DeletePolicyCondition(ctx context.Context, policyConditionUUID uuid.UUID) (err error) {
	return d.Client.PolicyCondition.Delete(ctx, policyConditionUUID)
}
