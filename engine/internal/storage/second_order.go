package storage

import "context"

type SecondOrderMarker struct {
	EndpointURL string
	Parameter   string
	Marker      string
}

func (db *DB) SaveSecondOrderMarker(scanID, endpointURL, parameter, marker string) error {
	return db.SaveSecondOrderMarkerContext(context.Background(), scanID, endpointURL, parameter, marker)
}

func (db *DB) SaveSecondOrderMarkerContext(ctx context.Context, scanID, endpointURL, parameter, marker string) error {
	_, err := db.execWriteContext(ctx, `
INSERT OR IGNORE INTO second_order_markers (scan_id, endpoint_url, parameter, marker)
VALUES (?, ?, ?, ?)`, scanID, endpointURL, parameter, marker)
	return err
}

func (db *DB) ListSecondOrderMarkers(scanID string) ([]SecondOrderMarker, error) {
	rows, err := db.conn.Query(`
SELECT endpoint_url, parameter, marker
FROM second_order_markers
WHERE scan_id = ?
ORDER BY id ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecondOrderMarker
	for rows.Next() {
		var marker SecondOrderMarker
		if err := rows.Scan(&marker.EndpointURL, &marker.Parameter, &marker.Marker); err != nil {
			return nil, err
		}
		out = append(out, marker)
	}
	return out, rows.Err()
}
