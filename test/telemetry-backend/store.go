package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nxtcoder17/ivy"
)

type telemetryRequest struct {
	AgentID     string            `json:"agent_id,omitempty"`
	RunID       string            `json:"run_id,omitempty"`
	Sequence    *int64            `json:"sequence,omitempty"`
	Schema      string            `json:"schema_version,omitempty"`
	Version     string            `json:"version,omitempty"`
	Cluster     string            `json:"cluster,omitempty"`
	Environment string            `json:"environment,omitempty"`
	K8sCluster  string            `json:"kubernetes_cluster,omitempty"`
	Targets     []json.RawMessage `json:"targets,omitempty"`
}

type telemetryRecord struct {
	ID          int64           `json:"id"`
	ReceivedAt  time.Time       `json:"received_at"`
	AgentID     string          `json:"agent_id"`
	RunID       string          `json:"run_id,omitempty"`
	Sequence    *int64          `json:"sequence,omitempty"`
	Schema      string          `json:"schema_version,omitempty"`
	Version     string          `json:"version,omitempty"`
	Cluster     string          `json:"cluster,omitempty"`
	Environment string          `json:"environment,omitempty"`
	TargetCount int             `json:"target_count"`
	Payload     json.RawMessage `json:"payload"`
}

type store struct{ db *sql.DB }

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	s := &store{db: db}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS telemetry_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  run_id TEXT,
  sequence INTEGER,
  schema_version TEXT,
  version TEXT,
  cluster TEXT,
  environment TEXT,
  target_count INTEGER NOT NULL DEFAULT 0,
  payload TEXT NOT NULL,
  UNIQUE(agent_id, sequence)
);
CREATE INDEX IF NOT EXISTS telemetry_events_agent_idx ON telemetry_events(agent_id);`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize sqlite schema: %w", err)
	}
	return s, nil
}

func (s *store) Close() error { return s.db.Close() }

func (s *store) insert(req telemetryRequest, payload []byte) (telemetryRecord, bool, error) {
	agentID := req.AgentID
	if agentID == "" {
		agentID = "legacy:" + req.K8sCluster
		if req.K8sCluster == "" {
			agentID = "legacy:unknown"
		}
	}
	cluster := req.Cluster
	if cluster == "" {
		cluster = req.K8sCluster
	}
	result, err := s.db.Exec(`INSERT OR IGNORE INTO telemetry_events
(received_at, agent_id, run_id, sequence, schema_version, version, cluster, environment, target_count, payload)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, time.Now().UTC().Format(time.RFC3339Nano), agentID,
		req.RunID, req.Sequence, req.Schema, req.Version, cluster, req.Environment, len(req.Targets), string(payload))
	if err != nil {
		return telemetryRecord{}, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return telemetryRecord{}, false, err
	}
	duplicate := changed == 0
	query := `SELECT id, received_at, agent_id, run_id, sequence, schema_version, version, cluster, environment, target_count, payload FROM telemetry_events WHERE id = last_insert_rowid()`
	args := []any{}
	if duplicate {
		query = `SELECT id, received_at, agent_id, run_id, sequence, schema_version, version, cluster, environment, target_count, payload FROM telemetry_events WHERE agent_id = ? AND sequence = ?`
		args = []any{agentID, *req.Sequence}
	}
	var r telemetryRecord
	var received string
	var runID, schema, version, environment sql.NullString
	var sequence sql.NullInt64
	var payloadText string
	if err := s.db.QueryRow(query, args...).Scan(&r.ID, &received, &r.AgentID, &runID, &sequence, &schema,
		&version, &r.Cluster, &environment, &r.TargetCount, &payloadText); err != nil {
		return telemetryRecord{}, duplicate, err
	}
	r.ReceivedAt, err = time.Parse(time.RFC3339Nano, received)
	if err != nil {
		return telemetryRecord{}, duplicate, err
	}
	r.RunID, r.Schema, r.Version, r.Environment = runID.String, schema.String, version.String, environment.String
	r.Payload = json.RawMessage(payloadText)
	if sequence.Valid {
		r.Sequence = &sequence.Int64
	}
	return r, duplicate, nil
}

func (s *store) handleTelemetry(c *ivy.Context) error {
	if token := os.Getenv("TELEMETRY_BACKEND_TOKEN"); token != "" && c.GetHeaders().Get("postman-insights-verification-token") != token {
		return c.Status(401).JSON(map[string]string{"error": "invalid verification token"})
	}
	var payload map[string]any
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(400).JSON(map[string]string{"error": "invalid JSON payload"})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return c.Status(400).JSON(map[string]string{"error": "invalid JSON payload"})
	}
	var telemetry telemetryRequest
	if err := json.Unmarshal(encoded, &telemetry); err != nil {
		return c.Status(400).JSON(map[string]string{"error": "invalid telemetry payload"})
	}
	if telemetry.Schema != "" && telemetry.Schema != "v1" {
		return c.Status(400).JSON(map[string]string{"error": "unsupported schema_version"})
	}
	record, duplicate, err := s.insert(telemetry, encoded)
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(map[string]any{"accepted": true, "duplicate": duplicate, "id": record.ID})
}

func (s *store) inspectTelemetry(c *ivy.Context) error {
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, received_at, agent_id, run_id, sequence, schema_version, version, cluster, environment, target_count, payload FROM telemetry_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	defer rows.Close()
	var records []telemetryRecord
	for rows.Next() {
		var record telemetryRecord
		var received string
		var runID, schema, version, environment sql.NullString
		var sequence sql.NullInt64
		var payloadText string
		if err := rows.Scan(&record.ID, &received, &record.AgentID, &runID, &sequence, &schema, &version,
			&record.Cluster, &environment, &record.TargetCount, &payloadText); err != nil {
			return c.Status(500).JSON(map[string]string{"error": err.Error()})
		}
		record.ReceivedAt, err = time.Parse(time.RFC3339Nano, received)
		if err != nil {
			return c.Status(500).JSON(map[string]string{"error": err.Error()})
		}
		record.RunID, record.Schema, record.Version, record.Environment = runID.String, schema.String, version.String, environment.String
		record.Payload = json.RawMessage(payloadText)
		if sequence.Valid {
			record.Sequence = &sequence.Int64
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(records)
}
