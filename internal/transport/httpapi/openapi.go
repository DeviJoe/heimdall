package httpapi

import (
	"net/http"
)

func (s *Server) swaggerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/openapi.json", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(w, r, "api_docs.read", "*") {
			return
		}
		JSON(w, 200, openAPI())
	}))
	mux.HandleFunc("GET /swagger", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(w, r, "api_docs.read", "*") {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>Heimdall API</title><link rel="stylesheet" href="/swagger-assets/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="/swagger-assets/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/api/v1/openapi.json',dom_id:'#swagger-ui',deepLinking:true,filter:true,docExpansion:'none',displayRequestDuration:true,defaultModelsExpandDepth:1,persistAuthorization:false,requestInterceptor:r=>{const method=(r.method||'GET').toUpperCase();if(!['GET','HEAD','OPTIONS'].includes(method)){if(!confirm('Этот API-запрос изменяет данные или доступ. Продолжить?'))throw new Error('Действие отменено');r.headers=r.headers||{};r.headers['X-Heimdall-CSRF']='1'}r.credentials='same-origin';return r}})</script></body></html>`))
	}))
}
