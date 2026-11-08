package db

import (
	"context"
	"encoding/json"
)

// RepairNullToolProperties fixes the invalid no-argument schema emitted by older
// built-ins, preserving descriptions, bindings, switches and other schema fields.
// Only an unchanged managed configuration receives a new ownership fingerprint.
func (d *DB) RepairNullToolProperties(ctx context.Context) (int, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT key,description,schema FROM tools
 WHERE system AND schema->>'type'='object' AND schema->'properties'='null'::jsonb
 ORDER BY key FOR UPDATE`)
	if err != nil {
		return 0, err
	}
	type item struct {
		key, description string
		schema           json.RawMessage
	}
	var items []item
	for rows.Next() {
		var row item
		if err = rows.Scan(&row.key, &row.description, &row.schema); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, row := range items {
		before, err := ConfigFingerprint(ToolConfigContract{Description: row.description, Schema: row.schema})
		if err != nil {
			return 0, err
		}
		var schema map[string]any
		if err = json.Unmarshal(row.schema, &schema); err != nil {
			return 0, err
		}
		schema["properties"] = map[string]any{}
		raw, err := json.Marshal(schema)
		if err != nil {
			return 0, err
		}
		after, err := ConfigFingerprint(ToolConfigContract{Description: row.description, Schema: raw})
		if err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE tools SET schema=$2,updated_at=now() WHERE key=$1`, row.key, raw); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE managed_config SET fingerprint=$3,updated_at=now()
 WHERE kind='tool' AND resource_key=$1 AND fingerprint=$2`, row.key, before, after); err != nil {
			return 0, err
		}
	}
	return len(items), tx.Commit()
}
