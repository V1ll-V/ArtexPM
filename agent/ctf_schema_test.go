package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Exercise the actual provider serialization against a gateway that rejects the
// invalid properties:null schema reported by users. Never contact a real model.
func TestCTFToolSchemasAcceptedByProviders(t *testing.T) {
	for _, format := range []llm.Format{llm.FormatAnthropic, llm.FormatOpenAI, llm.FormatOpenAIResponses} {
		for _, stream := range []bool{false, true} {
			for _, legacy := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/stream=%t/legacy=%t", format, stream, legacy), func(t *testing.T) {
					var schemas []llm.ToolSchema
					for _, tool := range ctfTools(nil, 1, 1, "") {
						if legacy && (tool.Name() == "ctf_tools" || tool.Name() == "ctf_status") {
							tool = DecorateTool(tool, "persisted description", map[string]any{"type": "object", "properties": nil})
						}
						schemas = append(schemas, llm.ToolSchema{Name: tool.Name(), Description: tool.Description(), InputSchema: tool.InputSchema()})
					}
					calls := 0
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						var body map[string]any
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
							http.Error(w, "invalid JSON", 400)
							return
						}
						tools, _ := body["tools"].([]any)
						if len(tools) != len(schemas) {
							t.Errorf("tool definitions missing: %d", len(tools))
						}
						for _, raw := range tools {
							tool := raw.(map[string]any)
							var input any
							switch format {
							case llm.FormatAnthropic:
								input = tool["input_schema"]
							case llm.FormatOpenAI:
								input = tool["function"].(map[string]any)["parameters"]
							default:
								input = tool["parameters"]
							}
							schema, object := input.(map[string]any)
							props, validProps := schema["properties"].(map[string]any)
							if !object || schema["type"] != "object" || !validProps || props == nil {
								t.Errorf("provider received invalid schema: %v", tool)
								http.Error(w, "Invalid schema: null is not of type object", 400)
								return
							}
						}
						writeSchemaFixtureResponse(w, format, stream)
					}))
					defer srv.Close()
					cfg := Config{Format: format, BaseURL: srv.URL, APIKey: "local-fake-key", Model: "local-schema-fixture", Retry: RetryConfig{ConnectAttempts: -1}}
					provider, err := cfg.NewProvider()
					if err != nil {
						t.Fatal(err)
					}
					req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("validate local tool schemas")}, Tools: schemas, MaxTokens: 32}
					var response strings.Builder
					if stream {
						for event, err := range provider.Stream(t.Context(), req) {
							if err != nil {
								t.Fatal(err)
							}
							if event.Type == llm.SETextDelta {
								response.WriteString(event.Text)
							}
						}
					} else {
						message, _, _, err := provider.Complete(t.Context(), req)
						if err != nil {
							t.Fatal(err)
						}
						response.WriteString(message.Text())
					}
					if response.String() != "accepted" || calls != 1 {
						t.Fatalf("response=%q calls=%d", response.String(), calls)
					}
				})
			}
		}
	}
}

func writeSchemaFixtureResponse(w http.ResponseWriter, format llm.Format, stream bool) {
	w.Header().Set("Content-Type", "application/json")
	if !stream {
		switch format {
		case llm.FormatAnthropic:
			io.WriteString(w, `{"id":"local","type":"message","role":"assistant","content":[{"type":"text","text":"accepted"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
		case llm.FormatOpenAI:
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"accepted"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
		default:
			io.WriteString(w, `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"accepted"}]}],"usage":{"input_tokens":1,"output_tokens":1}}`)
		}
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	switch format {
	case llm.FormatAnthropic:
		io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"accepted\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	case llm.FormatOpenAI:
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"accepted\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	default:
		io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"accepted\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")
	}
}

func TestDecorateToolRepairsNullPropertiesWithoutMutatingOverrides(t *testing.T) {
	base := ctfCatalogTools()[0]
	for _, props := range []any{nil, map[string]any(nil)} {
		schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false, "description": "custom constraint"}
		before, _ := json.Marshal(schema)
		tool := DecorateTool(base, "custom description", schema)
		after, _ := json.Marshal(schema)
		if string(before) != string(after) {
			t.Fatal("modified caller's schema")
		}
		if props, ok := tool.InputSchema()["properties"].(map[string]any); !ok || props == nil {
			t.Fatal("legacy null properties not repaired")
		}
		if tool.Description() != "custom description" || tool.InputSchema()["additionalProperties"] != false || tool.InputSchema()["description"] != "custom constraint" {
			t.Fatal("repair discarded custom settings")
		}
	}
}
