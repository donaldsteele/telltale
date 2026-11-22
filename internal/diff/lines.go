package diff

// LineChange is one added or deleted line. Line is the 1-based line number in
// the old text for a "del" and in the new text for an "add".
type LineChange struct {
	Line int
	Old  string
	New  string
	Op   string // "add" or "del"
}

// diffLines returns the line-level difference between a and b using a
// longest-common-subsequence table. Deletions precede additions at the same
// position.
func diffLines(a, b []string) []LineChange {
	// Trim the common prefix and suffix so the table stays small.
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	sa, sb := a[pre:], b[pre:]
	for len(sa) > 0 && len(sb) > 0 && sa[len(sa)-1] == sb[len(sb)-1] {
		sa, sb = sa[:len(sa)-1], sb[:len(sb)-1]
	}
	n, m := len(sa), len(sb)
	t := make([][]int32, n+1)
	for i := range t {
		t[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if sa[i] == sb[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else if t[i+1][j] >= t[i][j+1] {
				t[i][j] = t[i+1][j]
			} else {
				t[i][j] = t[i][j+1]
			}
		}
	}
	var out []LineChange
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && sa[i] == sb[j]:
			i++
			j++
		case i < n && (j >= m || t[i+1][j] >= t[i][j+1]):
			out = append(out, LineChange{Line: pre + i + 1, Old: sa[i], Op: "del"})
			i++
		default:
			out = append(out, LineChange{Line: pre + j + 1, New: sb[j], Op: "add"})
			j++
		}
	}
	return out
}
