package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestAuthFileConcurrencyViewPreservesPaginationAndLookup(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	registerPaginatedAuthFiles(t, authDir, manager)
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	for _, query := range []string{"", "&page=2&page_size=2", "&name=Alpha.json&auth_index=idx-Alpha.json", "&page=99&page_size=2"} {
		t.Run(query, func(t *testing.T) {
			full := requestAuthFilesPage(t, handler, "/v8/management/auth-files?"+strings.TrimPrefix(query, "&"))
			light := requestAuthFilesPage(t, handler, "/v8/management/auth-files?view=concurrency"+query)
			if !equalStrings(authFileNames(full.Files), authFileNames(light.Files)) || full.Total != light.Total || full.HasMore != light.HasMore {
				t.Fatalf("concurrency view changed inventory: full=%#v light=%#v", full, light)
			}
			for _, file := range light.Files {
				status, ok := file["concurrency"].(map[string]any)
				if !ok || status["current"] != float64(0) || status["limit"] != nil {
					t.Fatalf("unlimited status = %#v", file)
				}
				if len(file) != 4 {
					t.Fatalf("light view contains credential details: %#v", file)
				}
			}
		})
	}
}

func TestAuthFileConcurrencyPatchPersistsAndRejectsInvalidLimits(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	authDir := t.TempDir()
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(authDir)
	manager := coreauth.NewManager(store, nil, nil)
	fileName := "limited.json"
	filePath := filepath.Join(authDir, fileName)
	if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{
		ID: fileName, FileName: fileName, Provider: "codex",
		Attributes: map[string]string{"path": filePath}, Metadata: map[string]any{"type": "codex"},
	}); errRegister != nil {
		t.Fatal(errRegister)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	for _, value := range []string{"3", "-1", "1.5", `"3"`, "1000001", "0", "null"} {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPatch, "/v8/management/auth-files/fields", strings.NewReader(`{"name":"limited.json","max_concurrency":`+value+`}`))
		ctx.Request.Header.Set("Content-Type", "application/json")
		handler.PatchAuthFileFields(ctx)
		valid := value == "3" || value == "0" || value == "null"
		if !valid {
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("invalid limit %s: %d %s", value, recorder.Code, recorder.Body.String())
			}
			continue
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("limit %s: %d %s", value, recorder.Code, recorder.Body.String())
		}
		updated, _ := manager.GetByID(fileName)
		status := manager.CredentialConcurrency(updated)
		if (value == "3" && (status.Limit == nil || *status.Limit != 3)) || (value != "3" && status.Limit != nil) {
			t.Fatalf("limit %s runtime status = %#v", value, status)
		}
		raw, errRead := os.ReadFile(filePath)
		if errRead != nil {
			t.Fatal(errRead)
		}
		var persisted map[string]any
		if errDecode := json.Unmarshal(raw, &persisted); errDecode != nil {
			t.Fatal(errDecode)
		}
		want := map[string]any{"3": float64(3), "0": float64(0), "null": nil}[value]
		if persisted[coreauth.MetadataMaxConcurrency] != want {
			t.Fatalf("limit %s persisted = %#v", value, persisted[coreauth.MetadataMaxConcurrency])
		}
	}
}
