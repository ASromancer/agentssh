package ui

import "net/http"

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/lock", func(w http.ResponseWriter, r *http.Request) {
		if err := s.opt.Backend.Lock(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	})
}
