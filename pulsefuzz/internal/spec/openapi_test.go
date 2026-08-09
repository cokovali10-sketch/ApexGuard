package spec

import (
	"os"
	"path/filepath"
	"testing"
)

const demoSpec = `{
  "openapi": "3.0.0",
  "info": {"title":"demo","version":"1.0"},
  "paths": {
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "parameters": [
          {"name":"id","in":"path","required":true,"schema":{"type":"integer","example":42}},
          {"name":"verbose","in":"query","schema":{"type":"boolean"}}
        ],
        "responses": {"200":{"description":"ok"}}
      },
      "delete": {
        "operationId": "deleteUser",
        "parameters": [{"name":"id","in":"path","schema":{"type":"integer"}}],
        "responses": {"200":{"description":"ok"}}
      }
    },
    "/users": {
      "post": {
        "operationId": "createUser",
        "requestBody": {
          "content": {
            "application/json": {
              "example": {"username":"alice"},
              "schema": {"type":"object","properties":{
                "username":{"type":"string"},
                "balance":{"type":"number","format":"float"},
                "active":{"type":"boolean"}
              }}
            }
          }
        },
        "responses": {"201":{"description":"created"}}
      }
    }
  }
}`

func TestParseOpenAPI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openapi.json")
	if err := os.WriteFile(path, []byte(demoSpec), 0o644); err != nil {
		t.Fatal(err)
	}

	ops, err := ParseOpenAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 3 {
		t.Fatalf("expected 3 operations, got %d", len(ops))
	}

	byKey := map[string]Operation{}
	for _, op := range ops {
		byKey[op.Method+" "+op.Path] = op
	}

	getUser := byKey["get /users/{id}"]
	if getUser.Params["id"] != float64(42) {
		t.Fatalf("expected id=42, got %#v", getUser.Params["id"])
	}
	if getUser.Params["verbose"] != false {
		t.Fatalf("expected verbose=false, got %#v", getUser.Params["verbose"])
	}

	create := byKey["post /users"]
	if create.ExampleBody["username"] != "alice" {
		t.Fatalf("explicit example not honored: %#v", create.ExampleBody)
	}

	if _, ok := byKey["delete /users/{id}"]; !ok {
		t.Fatal("delete operation missing")
	}
}

func TestParseOpenAPIInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"paths":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOpenAPI(path); err == nil {
		t.Fatal("expected error for invalid json")
	}
}
