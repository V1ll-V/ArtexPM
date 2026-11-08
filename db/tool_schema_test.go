package db

import (
	"encoding/json"
	"testing"
)

func TestRepairNullToolPropertiesPreservesUserConfiguration(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	old := json.RawMessage(`{"type":"object","properties":null,"additionalProperties":false,"description":"schema note"}`)
	for _, key := range []string{"schema_owned", "schema_edited"} {
		if err = d.SeedTool(key, "original description", old, json.RawMessage(`["custom-agent"]`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.Exec(`UPDATE tools SET enabled=false,deferred=true WHERE key IN ('schema_owned','schema_edited')`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE tools SET description='user description' WHERE key='schema_edited'`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO tools(key,system,description,schema) VALUES('schema_custom',false,'custom',$1)`, old); err != nil {
		t.Fatal(err)
	}
	var baseline string
	if err = d.QueryRow(`SELECT fingerprint FROM managed_config WHERE kind='tool' AND resource_key='schema_edited'`).Scan(&baseline); err != nil {
		t.Fatal(err)
	}
	n, err := d.RepairNullToolProperties(t.Context())
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	for _, key := range []string{"schema_owned", "schema_edited"} {
		row, err := d.GetTool(key)
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err = json.Unmarshal(row.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		if props, ok := schema["properties"].(map[string]any); !ok || props == nil || len(props) != 0 {
			t.Fatal("properties not repaired", schema)
		}
		if schema["additionalProperties"] != false || schema["description"] != "schema note" || row.Enabled || !row.Deferred || len(row.Agents) != 1 || row.Agents[0] != "custom-agent" {
			t.Fatal("user settings changed", row, schema)
		}
		var fingerprint string
		if err = d.QueryRow(`SELECT fingerprint FROM managed_config WHERE kind='tool' AND resource_key=$1`, key).Scan(&fingerprint); err != nil {
			t.Fatal(err)
		}
		if key == "schema_owned" {
			expected, err := ConfigFingerprint(ToolConfigContract{Description: row.Description, Schema: row.Schema})
			if err != nil || fingerprint != expected || row.Description != "original description" {
				t.Fatal("owned fingerprint not advanced", err)
			}
		} else if fingerprint != baseline || row.Description != "user description" {
			t.Fatal("user customization incorrectly marked as managed")
		}
	}
	var customUnchanged bool
	if err = d.QueryRow(`SELECT schema->'properties'='null'::jsonb FROM tools WHERE key='schema_custom'`).Scan(&customUnchanged); err != nil || !customUnchanged {
		t.Fatal("custom tool was rewritten", err)
	}
	if n, err = d.RepairNullToolProperties(t.Context()); err != nil || n != 0 {
		t.Fatal("repair not idempotent", n, err)
	}
}
