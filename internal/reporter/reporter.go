package reporter

import (
	"io"

	"github.com/pssht/dotscrub/internal/scanner"
)

type Reporter interface {
	Report(w io.Writer, findings []scanner.Finding) error
}
