package location

import (
	"github.com/akitasoftware/akita-libs/akiuri"
	"github.com/pkg/errors"
)

// Implements pflag.Value interface.
type Location struct {
	AkitaURI *akiuri.URI
}

func (l Location) String() string {
	if l.AkitaURI != nil {
		return l.AkitaURI.String()
	}
	return ""
}

func (l *Location) Set(raw string) error {
	if len(raw) == 0 {
		return errors.Errorf("location cannot be empty")
	}

	u, err := akiuri.Parse(raw)
	if err != nil {
		return errors.Wrapf(err, "unable to parse akiuri %q", raw)
	}

	l.AkitaURI = &u
	return nil
}

func (Location) Type() string {
	return "location"
}

func (l Location) IsSet() bool {
	return l.AkitaURI != nil
}
