package httpapi

import (
	"Heimdall/internal/application"
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"time"
)

func (s *Server) mcpHandler() http.Handler {
	handler := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		p := Principal(request.Context())
		server := mcp.NewServer(&mcp.Implementation{Name: "heimdall", Version: "0.1.0"}, nil)
		mcp.AddTool(server, &mcp.Tool{Name: "list_nodes", Description: "List UNIX nodes visible to the caller and their confirmed synchronization state."}, func(ctx context.Context, r *mcp.CallToolRequest, in struct {
			Limit  int    `json:"limit,omitempty"`
			Cursor string `json:"cursor,omitempty"`
			Query  string `json:"query,omitempty"`
			Group  string `json:"group_id,omitempty"`
		}) (*mcp.CallToolResult, any, error) {
			settings, err := s.Store.Settings(ctx)
			if err != nil {
				return nil, nil, err
			}
			v, next, err := s.Store.QueryNodesPage(ctx, p, time.Duration(settings.OfflineSeconds)*time.Second, in.Limit, in.Cursor, in.Group, in.Query)
			return nil, map[string]any{"items": v, "next_cursor": next}, err
		})
		mcp.AddTool(server, &mcp.Tool{Name: "list_users", Description: "List users visible to the caller."}, func(ctx context.Context, r *mcp.CallToolRequest, in struct {
			Limit  int    `json:"limit,omitempty"`
			Cursor string `json:"cursor,omitempty"`
			Query  string `json:"query,omitempty"`
		}) (*mcp.CallToolResult, any, error) {
			v, next, err := s.Store.SearchUsersPage(ctx, p, in.Limit, in.Cursor, in.Query)
			return nil, map[string]any{"items": v, "next_cursor": next}, err
		})
		for _, definition := range []struct{ Name, Collection string }{
			{"list_incidents", "incidents"}, {"list_operations", "operations"}, {"list_groups", "groups"}, {"list_people_groups", "user-groups"}, {"list_unix_groups", "unix-groups"}, {"list_roles", "roles"}, {"list_audit", "audit"}, {"list_security_events", "security/events"},
		} {
			mcp.AddTool(server, &mcp.Tool{Name: definition.Name, Description: "Search a bounded page of authorized " + definition.Collection + "; use next_cursor for the next page."}, func(ctx context.Context, r *mcp.CallToolRequest, in struct {
				Limit  int    `json:"limit,omitempty"`
				Cursor string `json:"cursor,omitempty"`
				Query  string `json:"query,omitempty"`
				Status string `json:"status,omitempty"`
			}) (*mcp.CallToolResult, any, error) {
				result, err := s.Store.ReadPage(ctx, p, definition.Collection, application.PageQuery{Limit: in.Limit, After: in.Cursor, Search: in.Query, Status: in.Status})
				return nil, map[string]any{"items": result.Items, "next_cursor": result.Next}, err
			})
		}
		mcp.AddTool(server, &mcp.Tool{Name: "user_sync_status", Description: "Get per-node synchronization status for a user."}, func(ctx context.Context, r *mcp.CallToolRequest, in struct {
			UserID string `json:"user_id" jsonschema:"User UUID"`
			Limit  int    `json:"limit,omitempty"`
			Cursor string `json:"cursor,omitempty"`
		}) (*mcp.CallToolResult, any, error) {
			v, next, err := s.Store.UserSyncPage(ctx, p, in.UserID, in.Limit, in.Cursor)
			return nil, map[string]any{"items": v, "next_cursor": next}, err
		})
		mcp.AddTool(server, &mcp.Tool{Name: "retry_node_sync", Description: "Request reapplication of UNIX access configuration; requires sync.retry permission for the node group."}, func(ctx context.Context, r *mcp.CallToolRequest, in struct {
			NodeID string `json:"node_id" jsonschema:"Node UUID"`
		}) (*mcp.CallToolResult, any, error) {
			id, err := s.Store.RetryNode(ctx, p, in.NodeID)
			return nil, map[string]string{"operation_id": id}, err
		})
		mcp.AddTool(server, &mcp.Tool{Name: "disable_user", Description: "Block a user and queue removal of Linux keys, passwords and sudo rights. Requires global users.manage. Offline nodes remain pending until acknowledgement."}, func(ctx context.Context, r *mcp.CallToolRequest, in struct {
			UserID string `json:"user_id" jsonschema:"User UUID"`
		}) (*mcp.CallToolResult, any, error) {
			id, err := s.Store.SetUserStatus(ctx, p, in.UserID, "disabled")
			return nil, map[string]string{"operation_id": id}, err
		})
		return server
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && origin != s.Config.Server.PublicURL {
			Fail(w, application.ErrForbidden)
			return
		}
		p, err := s.authenticate(r, "mcp")
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="Heimdall MCP"`)
			JSON(w, 401, map[string]string{"error": "A valid MCP audience token is required"})
			return
		}
		if p.Restricted {
			Fail(w, application.ErrForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, p)))
	})
}
