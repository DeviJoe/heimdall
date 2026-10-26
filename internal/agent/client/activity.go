package client

import (
	"Heimdall/api/gen/agentv1"
	"Heimdall/internal/synchronization"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"
)

func reportActivity(ctx context.Context, rpc agentv1.AgentServiceClient, helper *http.Client) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := activityBatch(ctx, rpc, helper); err != nil {
			slog.Warn("security telemetry delivery pending", "error", err)
		}
	}
}
func activityBatch(ctx context.Context, rpc agentv1.AgentServiceClient, helper *http.Client) error {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(bounded, "GET", "http://helper/events", nil)
	response, err := helper.Do(request)
	if err != nil {
		return err
	}
	var events []synchronization.ActivityEvent
	err = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&events)
	response.Body.Close()
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return errors.New("security spool unavailable")
	}
	if len(events) == 0 {
		return nil
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return err
	}
	ack, err := rpc.ReportActivity(bounded, &agentv1.ActivityRequest{Json: raw})
	if err != nil {
		return err
	}
	raw, err = json.Marshal(ack.AcknowledgedIds)
	if err != nil {
		return err
	}
	request, _ = http.NewRequestWithContext(bounded, "POST", "http://helper/events/ack", bytes.NewReader(raw))
	response, err = helper.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		return errors.New("security spool acknowledgement failed")
	}
	return nil
}
