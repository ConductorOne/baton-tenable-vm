package connector

import (
	"context"
	"fmt"
	"strconv"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/session"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
)

// Session-store cache prefixes used to namespace upstream data for the duration
// of a single sync. Replacing the former connector-level mutex caches, these are
// backed by the SDK session store so state is shared across resource-type
// builders without in-memory maps or TTL bookkeeping. Every read/write is also
// scoped to the current SyncID so state never leaks across syncs.
const (
	usersCachePrefix       = "users"
	permissionsCachePrefix = "permissions"
	groupsCachePrefix      = "groups"
)

// getCachedUsers returns all users keyed by UUID. When a session store is
// available it reads from the cache first and, on a miss, fetches the full user
// list once from the API and writes it back so subsequent builders within the
// same sync get cache hits. When no session is present (e.g. CLI/local runs) it
// falls back to the API without caching.
func getCachedUsers(ctx context.Context, c *client.TenableVMClient, opts rs.SyncOpAttrs) (map[string]*client.User, annotations.Annotations, error) {
	if opts.Session != nil {
		cached, err := session.GetAllJSON[client.User](ctx, opts.Session,
			sessions.WithSyncID(opts.SyncID),
			sessions.WithPrefix(usersCachePrefix),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-tenable-vm: failed to read users from session store: %w", err)
		}
		if len(cached) > 0 {
			usersMap := make(map[string]*client.User, len(cached))
			for uuid := range cached {
				user := cached[uuid]
				usersMap[uuid] = &user
			}
			return usersMap, nil, nil
		}
	}

	users, annos, err := c.GetUsers(ctx)
	if err != nil {
		return nil, annos, err
	}
	if len(users) == 0 {
		return map[string]*client.User{}, annos, nil
	}

	usersMap := make(map[string]*client.User, len(users))
	toCache := make(map[string]client.User, len(users))
	for i := range users {
		user := users[i]
		usersMap[user.UUID] = &user
		toCache[user.UUID] = user
	}

	if opts.Session != nil {
		if err := session.SetManyJSON(ctx, opts.Session, toCache,
			sessions.WithSyncID(opts.SyncID),
			sessions.WithPrefix(usersCachePrefix),
		); err != nil {
			return nil, annos, fmt.Errorf("baton-tenable-vm: failed to write users to session store: %w", err)
		}
	}

	return usersMap, annos, nil
}

// getCachedPermissions returns all permissions keyed by permission UUID, reading
// from the session store when available and populating it from the API on a
// miss. Falls back to the API without caching when no session is present.
func getCachedPermissions(ctx context.Context, c *client.TenableVMClient, opts rs.SyncOpAttrs) (map[string]*client.Permission, annotations.Annotations, error) {
	if opts.Session != nil {
		cached, err := session.GetAllJSON[client.Permission](ctx, opts.Session,
			sessions.WithSyncID(opts.SyncID),
			sessions.WithPrefix(permissionsCachePrefix),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-tenable-vm: failed to read permissions from session store: %w", err)
		}
		if len(cached) > 0 {
			permissionsMap := make(map[string]*client.Permission, len(cached))
			for uuid := range cached {
				permission := cached[uuid]
				permissionsMap[uuid] = &permission
			}
			return permissionsMap, nil, nil
		}
	}

	permissions, annos, err := c.ListPermissions(ctx)
	if err != nil {
		return nil, annos, err
	}
	if len(permissions) == 0 {
		return map[string]*client.Permission{}, annos, nil
	}

	permissionsMap := make(map[string]*client.Permission, len(permissions))
	toCache := make(map[string]client.Permission, len(permissions))
	for i := range permissions {
		permission := permissions[i]
		permissionsMap[permission.UUID.String()] = &permission
		toCache[permission.UUID.String()] = permission
	}

	if opts.Session != nil {
		if err := session.SetManyJSON(ctx, opts.Session, toCache,
			sessions.WithSyncID(opts.SyncID),
			sessions.WithPrefix(permissionsCachePrefix),
		); err != nil {
			return nil, annos, fmt.Errorf("baton-tenable-vm: failed to write permissions to session store: %w", err)
		}
	}

	return permissionsMap, annos, nil
}

// getCachedGroups returns a map of group UUID to group ID, reading from the
// session store when available and populating it from the API on a miss. Used to
// resolve group subjects when emitting permission grants. Falls back to the API
// without caching when no session is present.
func getCachedGroups(ctx context.Context, c *client.TenableVMClient, opts rs.SyncOpAttrs) (map[string]string, annotations.Annotations, error) {
	if opts.Session != nil {
		cached, err := session.GetAllJSON[string](ctx, opts.Session,
			sessions.WithSyncID(opts.SyncID),
			sessions.WithPrefix(groupsCachePrefix),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-tenable-vm: failed to read groups from session store: %w", err)
		}
		if len(cached) > 0 {
			return cached, nil, nil
		}
	}

	groups, annos, err := c.GetGroups(ctx)
	if err != nil {
		return nil, annos, err
	}
	if len(groups) == 0 {
		return map[string]string{}, annos, nil
	}

	groupsMap := make(map[string]string, len(groups))
	for i := range groups {
		group := groups[i]
		groupsMap[group.UUID] = strconv.Itoa(group.ID)
	}

	if opts.Session != nil {
		if err := session.SetManyJSON(ctx, opts.Session, groupsMap,
			sessions.WithSyncID(opts.SyncID),
			sessions.WithPrefix(groupsCachePrefix),
		); err != nil {
			return nil, annos, fmt.Errorf("baton-tenable-vm: failed to write groups to session store: %w", err)
		}
	}

	return groupsMap, annos, nil
}
