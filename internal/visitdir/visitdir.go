// Package visitdir knows the one form of directory a server visit makes on
// a machine for the collector: /run, /var/tmp, /root or /tmp, then
// telltale. and eight letters or digits. The server's visits and the
// collector share it; it is a package of its own so that the collector
// build does not link the server's packages.
package visitdir

import "regexp"

var re = regexp.MustCompile(`^/(run|var/tmp|root|tmp)/telltale\.[A-Za-z0-9]{8}$`)

// Is reports whether d has the form of a directory a visit makes.
func Is(d string) bool { return re.MatchString(d) }
