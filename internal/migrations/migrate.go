package migrations

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Run executes all SQL migration files from the migrations/ directory in sorted order.
func Run(ctx context.Context, pool *pgxpool.Pool) error {
	files, err := filepath.Glob("migrations/*.sql")
	if err != nil {
		return fmt.Errorf("finding migration files: %w", err)
	}

	sort.Strings(files)

	for _, file := range files {
		//nolint:gosec // Safe because files are explicitly globbed from internal *.sql extensions
		sql, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading migration file %s: %w", file, err)
		}

		if _, err = pool.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("running migration %s: %w", file, err)
		}
	}

	return nil
}
