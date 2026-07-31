// Command test-server is an in-process mock of the Tenable Vulnerability
// Management API used for local/CI runs of baton-tenable-vm when no real-tenant
// credentials are available (and specifically when FedRAMP GovCloud credentials
// cannot be obtained). It mirrors the upstream auth header, paths, response
// shapes, and error envelope documented at developer.tenable.com.
//
// See cmd/test-server/README.md.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

const defaultPort = "8765"

func newMux(h *handlers) *http.ServeMux {
	mux := http.NewServeMux()
	auth := requireAPIKeys

	// Users
	// Doc URL: https://developer.tenable.com/reference/users-list
	mux.HandleFunc("GET /users", auth(h.listUsers))
	// Doc URL: https://developer.tenable.com/reference/users-create
	mux.HandleFunc("POST /users", auth(h.createUser))
	// Doc URL: https://developer.tenable.com/reference/users-details
	mux.HandleFunc("GET /users/{id}", auth(h.getUser))
	// Doc URL: https://developer.tenable.com/reference/users-edit
	mux.HandleFunc("PUT /users/{id}", auth(h.updateUser))
	// Doc URL: https://developer.tenable.com/reference/users-delete
	mux.HandleFunc("DELETE /users/{id}", auth(h.deleteUser))
	// Doc URL: https://developer.tenable.com/reference/users-enabled
	mux.HandleFunc("PUT /users/{id}/enabled", auth(h.setUserEnabled))

	// Groups
	// Doc URL: https://developer.tenable.com/reference/groups-list
	mux.HandleFunc("GET /groups", auth(h.listGroups))
	// Doc URL: https://developer.tenable.com/reference/groups-list-users
	mux.HandleFunc("GET /groups/{id}/users", auth(h.listGroupMembers))
	// Doc URL: https://developer.tenable.com/reference/groups-add-user
	mux.HandleFunc("POST /groups/{id}/users/{userId}", auth(h.addGroupMember))
	// Doc URL: https://developer.tenable.com/reference/groups-delete-user
	mux.HandleFunc("DELETE /groups/{id}/users/{userId}", auth(h.removeGroupMember))

	// Roles
	// Doc URL: https://developer.tenable.com/reference/access-control-roles-list
	mux.HandleFunc("GET /access-control/v1/roles", auth(h.listRoles))
	// Doc URL: https://developer.tenable.com/reference/access-control-users-role-list
	mux.HandleFunc("GET /access-control/v1/users/{uuid}/roles", auth(h.getUserRoles))
	// Doc URL: https://developer.tenable.com/reference/access-control-users-role-update
	mux.HandleFunc("PUT /access-control/v1/users/{uuid}/roles", auth(h.updateUserRoles))

	// Permissions
	// Doc URL: https://developer.tenable.com/reference/io-v3-access-control-permissions-list
	mux.HandleFunc("GET /api/v3/access-control/permissions", auth(h.listPermissions))
	// Doc URL: https://developer.tenable.com/reference/io-v3-access-control-permissions-details
	mux.HandleFunc("GET /api/v3/access-control/permissions/{uuid}", auth(h.getPermission))
	// Doc URL: https://developer.tenable.com/reference/io-v3-access-control-permission-update
	mux.HandleFunc("PUT /api/v3/access-control/permissions/{uuid}", auth(h.updatePermission))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	return mux
}

func run() error {
	port := flag.String("port", defaultPort, "TCP port to listen on")
	flag.Parse()

	h := &handlers{state: NewState()}
	srv := &http.Server{
		Addr:              ":" + *port,
		Handler:           newMux(h),
		ReadHeaderTimeout: 30 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "baton-tenable-vm test-server listening on http://localhost:%s\n", *port)
	fmt.Fprintf(os.Stderr, "  access-key: %s\n", testAccessKey)
	fmt.Fprintf(os.Stderr, "  secret-key: %s\n", testSecretKey)
	return srv.ListenAndServe()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
