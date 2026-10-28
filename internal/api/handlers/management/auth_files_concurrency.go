package management

import (
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// listAuthFileConcurrency avoids quota and credential detail work for passive polling.
func (h *Handler) listAuthFileConcurrency(c *gin.Context, pagination authFilesPagination) {
	nameFilter := strings.TrimSpace(c.Query("name"))
	authIndexFilter := strings.TrimSpace(c.Query("auth_index"))
	auths := h.authManager.List()
	matching := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if matchesAuthFileLookup(auth, nameFilter, authIndexFilter) && isAuthFileListable(auth) {
			matching = append(matching, auth)
		}
	}
	sort.Slice(matching, func(i, j int) bool {
		return compareAuthFileListOrder(matching[i], matching[j]) < 0
	})
	start, end := pagination.bounds(len(matching))
	files := make([]gin.H, 0, end-start)
	for _, auth := range matching[start:end] {
		files = append(files, gin.H{
			"id":          auth.ID,
			"auth_index":  lockedAuthIndex(auth),
			"name":        authFileListName(auth),
			"concurrency": h.authManager.CredentialConcurrency(auth),
		})
	}
	c.JSON(200, authFilesListResponse(time.Now().UTC(), files, pagination, len(matching), end))
}
