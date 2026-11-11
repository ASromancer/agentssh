package ui

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ASromancer/agentssh/internal/audit"
	"github.com/ASromancer/agentssh/internal/daemon"
	"github.com/ASromancer/agentssh/internal/hosts"
)

const maxBody = 1 << 20

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(v); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return false
	}
	return true
}

func (s *Server) routes(mux *http.ServeMux) {
	b := s.opt.Backend
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := b.Status()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]any{"status": st, "version": s.opt.Version})
	})
	mux.HandleFunc("GET /api/pending", func(w http.ResponseWriter, r *http.Request) {
		p, err := b.Pending()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, p)
	})
	mux.HandleFunc("POST /api/decide", func(w http.ResponseWriter, r *http.Request) {
		var a struct {
			ID                 int
			Choice, Note, Code string
		}
		if !readJSON(w, r, &a) {
			return
		}
		if err := b.Decide(daemon.DecideArgs{ID: a.ID, Choice: a.Choice, Note: a.Note, Code: a.Code}); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("GET /api/hosts", func(w http.ResponseWriter, r *http.Request) {
		h, err := b.HostList()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, h)
	})
	mux.HandleFunc("POST /api/admin/begin", func(w http.ResponseWriter, r *http.Request) {
		var a daemon.BeginArgs
		if !readJSON(w, r, &a) {
			return
		}
		rep, err := b.Begin(a)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("POST /api/admin/commit", func(w http.ResponseWriter, r *http.Request) {
		var a struct {
			Ticket                       int
			Code, Op, Name               string
			Host                         *hosts.Host
			Key, KeyPassphrase, Password string
		}
		if !readJSON(w, r, &a) {
			return
		}
		args := daemon.AdminArgs{Ticket: a.Ticket, Code: a.Code, Op: a.Op, Name: a.Name, Host: a.Host}
		if a.Key != "" {
			p, err := normalizeKey([]byte(a.Key), a.KeyPassphrase, a.Name)
			if err != nil {
				fail(w, err)
				return
			}
			args.PEM = p
		}
		if a.Password != "" {
			args.Password = []byte(a.Password)
		}
		rep, err := b.Admin(args)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]string{"out": rep.Out})
	})
	mux.HandleFunc("POST /api/unlock", func(w http.ResponseWriter, r *http.Request) {
		var a struct{ Pass string }
		if !readJSON(w, r, &a) {
			return
		}
		if err := b.Unlock(a.Pass); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("POST /api/lock", func(w http.ResponseWriter, r *http.Request) {
		if err := b.Lock(); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("GET /api/keys", func(w http.ResponseWriter, r *http.Request) {
		k, err := b.Keys()
		if err != nil {
			fail(w, err)
			return
		}
		if k == nil {
			k = []string{}
		}
		writeJSON(w, k)
	})
	mux.HandleFunc("GET /api/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		entries, total, err := readAudit(s.opt.AuditFile, q.Get("host"), q.Get("decision"), q.Get("since"), limit, offset)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]any{"entries": entries, "total": total})
	})
	mux.HandleFunc("GET /api/out/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id <= 0 {
			fail(w, errors.New("bad id"))
			return
		}
		text, err := daemon.ReadOutput(id, r.URL.Query().Get("grep"), r.URL.Query().Get("range"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]string{"text": text})
	})
	mux.HandleFunc("GET /api/doctor", func(w http.ResponseWriter, r *http.Request) {
		checks := []Check{}
		if s.opt.Doctor != nil {
			checks = s.opt.Doctor()
		}
		writeJSON(w, checks)
	})
	mux.HandleFunc("GET /events", s.events)
}

// normalizeKey turns an uploaded private key (possibly passphrase
// protected) into the unencrypted OpenSSH PEM the vault stores, like
// 'agentssh key import' does.
func normalizeKey(b []byte, passphrase, name string) ([]byte, error) {
	raw, err := ssh.ParseRawPrivateKey(b)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, errors.New("this key is protected: enter its passphrase")
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(b, []byte(passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(raw, "agentssh-"+name)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// readAudit returns audit entries newest first, filtered and paged.
// ponytail: reads the whole file per request; index or tail-read if logs get huge.
func readAudit(path, host, decision, since string, limit, offset int) ([]audit.Entry, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var sinceT time.Time
	if since != "" {
		t, err := time.ParseInLocation("2006-01-02", since, time.Local)
		if err != nil {
			return nil, 0, errors.New("since must be YYYY-MM-DD")
		}
		sinceT = t
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []audit.Entry{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var all []audit.Entry
	br := bufio.NewReader(f)
	for {
		line, err := br.ReadBytes('\n') // lines over 4 MiB or unparseable are skipped, not fatal
		if len(line) > 0 && len(line) <= 4<<20 {
			var e audit.Entry
			if json.Unmarshal(line, &e) == nil &&
				!(host != "" && e.Host != host) && !(decision != "" && e.Decision != decision) && !(!sinceT.IsZero() && e.Time.Before(sinceT)) {
				all = append(all, e)
			}
		}
		if err != nil {
			break
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.After(all[j].Time) })
	total := len(all)
	offset = max(0, min(offset, total))
	end := min(offset+limit, total)
	page := all[offset:end]
	if page == nil {
		page = []audit.Entry{}
	}
	return page, total, nil
}

// events streams "update" whenever pending requests, lock state or auth
// mode change, so the page refreshes without polling.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last, idle := "", 0
	for {
		st, _ := s.opt.Backend.Status()
		p, _ := s.opt.Backend.Pending()
		ids := make([]string, len(p))
		for i, x := range p {
			ids[i] = strconv.Itoa(x.ID)
		}
		cur := fmt.Sprintf("%v|%s|%s", st.Locked, st.Auth, strings.Join(ids, ","))
		if cur != last {
			last, idle = cur, 0
			fmt.Fprintf(w, "event: update\ndata: %d\n\n", len(p))
			fl.Flush()
		} else if idle++; idle >= 15 {
			idle = 0
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}
