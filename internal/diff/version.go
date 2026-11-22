package diff

import "strings"

// CompareVersions orders two Debian version strings (epoch:upstream-revision)
// and returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	ea, ua, ra := splitVersion(a)
	eb, ub, rb := splitVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := comparePart(ua, ub); c != 0 {
		return c
	}
	return comparePart(ra, rb)
}

func splitVersion(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		for _, c := range v[:i] {
			if c < '0' || c > '9' {
				epoch = 0
				goto rest
			}
			epoch = epoch*10 + int(c-'0')
		}
		v = v[i+1:]
	}
rest:
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// order is the sort weight of one character in a non-digit run: '~' lowest,
// then end of string, then letters, then everything else.
func order(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case c == '~':
		return -1
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func isDigit(s string, i int) bool { return i < len(s) && s[i] >= '0' && s[i] <= '9' }

func comparePart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a, i)) || (j < len(b) && !isDigit(b, j)) {
			oa, ob := order(a, i), order(b, j)
			if oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		si, sj := i, j
		for isDigit(a, i) {
			i++
		}
		for isDigit(b, j) {
			j++
		}
		if la, lb := i-si, j-sj; la != lb {
			if la < lb {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}
