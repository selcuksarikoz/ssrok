package server

import (
	"html/template"
	"log"
	"net/http"

	"ssrok/internal/ui"
)

type TemplateManager struct {
	Templates map[string]*template.Template
}

func NewTemplateManager() (*TemplateManager, error) {
	tmpls, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	return &TemplateManager{Templates: tmpls}, nil
}

func loadTemplates() (map[string]*template.Template, error) {
	tmpls := make(map[string]*template.Template)

	layoutContent, err := ui.Templates.ReadFile("layout.html")
	if err != nil {
		return nil, err
	}

	baseTmpl, err := template.New("layout").Parse(string(layoutContent))
	if err != nil {
		return nil, err
	}

	pages := []string{"login.html", "ratelimit.html", "notfound.html", "home.html", "error.html", "disconnected.html"}

	for _, page := range pages {
		pageContent, err := ui.Templates.ReadFile(page)
		if err != nil {
			return nil, err
		}

		pageTmpl, err := baseTmpl.Clone()
		if err != nil {
			return nil, err
		}

		_, err = pageTmpl.Parse(string(pageContent))
		if err != nil {
			return nil, err
		}

		tmpls[page] = pageTmpl
	}

	return tmpls, nil
}

func (tm *TemplateManager) Render(w http.ResponseWriter, name string, data map[string]interface{}) {
	tmpl, ok := tm.Templates[name]
	if !ok {
		log.Printf("Error: Template %s not found", name)
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing template %s: %v", name, err)
	}
}
