//go:build lab

// Command repo-server serves the lab's signed third-party APT repository: a
// static file server over one of the trees built into the image (see
// build.sh). "-tree a" is the repository as the vendor signs it; "-tree b" is
// the same repository signed with another key, for the scenario in which a
// machine is pointed at a swapped repository.
//
// It also answers requests in proxy form ("GET http://host/path"), so that
// the lab harness on the host, which cannot resolve the lab network's names,
// can fetch from it with HTTP_PROXY set to this server's address.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	tree := flag.String("tree", "a", "which tree under /repo to serve: a or b")
	listen := flag.String("listen", ":80", "address to listen on")
	root := flag.String("root", "/repo", "directory holding the trees")
	flag.Parse()
	dir := filepath.Join(*root, *tree)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		log.Fatalf("no tree %q under %s", *tree, *root)
	}
	log.SetFlags(0)
	files := http.FileServer(http.Dir(dir))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		files.ServeHTTP(w, r)
	})
	log.Printf("repo ready: tree %s on %s", *tree, *listen)
	log.Fatal(http.ListenAndServe(*listen, h))
}
