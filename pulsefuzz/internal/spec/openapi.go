// PulseFuzz — парсер OpenAPI v3 / GraphQL-схем.
// Идентифицирует операции, параметры, тело примера и безопасные поля.
package spec

import (
	"encoding/json"
	"fmt"
	"os"
)

// Operation — нормализованное описание HTTP-операции из OpenAPI v3.
type Operation struct {
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	Params      map[string]any `json:"params"`
	ExampleBody map[string]any `json:"example_body"`
}

type openAPIDoc struct {
	Paths map[string]map[string]*openAPIOperation `json:"paths"`
}

type openAPIOperation struct {
	Parameters []openAPIParam `json:"parameters"`
	RequestBody struct {
		Content map[string]struct {
			Schema openAPISchema `json:"schema"`
			Example any          `json:"example"`
		} `json:"content"`
	} `json:"requestBody"`
	Security []map[string][]string `json:"security"`
}

type openAPIParam struct {
	Name    string     `json:"name"`
	In      string     `json:"in"`
	Schema  openAPISchema `json:"schema"`
	Example any        `json:"example"`
}

type openAPISchema struct {
	Type     string                  `json:"type"`
	Format   string                  `json:"format"`
	Default  any                     `json:"default"`
	Example  any                     `json:"example"`
	Properties map[string]openAPISchema `json:"properties"`
	Items    *openAPISchema          `json:"items"`
}

// ParseOpenAPI загружает спецификацию и возвращает список операций.
// Поддерживаются также GraphQL-схемы (интроспекция), для демо — JSON-описание.
func ParseOpenAPI(path string) ([]Operation, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc openAPIDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid openapi json: %w", err)
	}

	var ops []Operation
	for path, methods := range doc.Paths {
		for method, op := range methods {
			if op == nil {
				continue
			}
			body := exampleFromSchema(op.RequestBody.Content, "application/json")
			params := map[string]any{}
			for _, p := range op.Parameters {
				params[p.Name] = schemaExample(&p.Schema, p.Example)
			}
			ops = append(ops, Operation{
				Method:      method,
				Path:        path,
				Params:      params,
				ExampleBody: body,
			})
		}
	}
	return ops, nil
}

// exampleFromSchema строит пример тела из schema.properties, либо берёт явный example.
func exampleFromSchema(content map[string]struct {
	Schema  openAPISchema `json:"schema"`
	Example any           `json:"example"`
}, mediaType string) map[string]any {
	mt, ok := content[mediaType]
	if !ok {
		// первый доступный медиатип
		for _, v := range content {
			mt = v
			break
		}
	}
	if mt.Example != nil {
		if m, ok := mt.Example.(map[string]any); ok {
			return m
		}
	}
	if m, ok := schemaExample(&mt.Schema, nil).(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// schemaExample строит пример значения из типа схемы.
func schemaExample(s *openAPISchema, explicit any) any {
	if explicit != nil {
		return explicit
	}
	if s == nil {
		return nil
	}
	if s.Example != nil {
		return s.Example
	}
	switch s.Type {
	case "object":
		out := map[string]any{}
		for k, v := range s.Properties {
			out[k] = schemaExample(&v, v.Example)
		}
		return out
	case "array":
		if s.Items != nil {
			return []any{schemaExample(s.Items, nil)}
		}
		return []any{}
	case "integer", "number":
		return 0
	case "boolean":
		return false
	default:
		return "string"
	}
}
