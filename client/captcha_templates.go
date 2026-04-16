package main

import (
	"bytes"
	"embed"
	"html/template"
	"log"
)

//go:embed templates/*.html.tmpl
var captchaTemplateFS embed.FS

var captchaTemplates = template.Must(
	template.New("captcha").ParseFS(captchaTemplateFS, "templates/*.html.tmpl"),
)

type captchaFormPageData struct {
	PageTitle    string
	Headline     string
	Summary      string
	ImageURL     string
	SolvePath    string
	CompletePath string
	CancelPath   string
}

type captchaErrorPageData struct {
	PageTitle  string
	Title      string
	Summary    string
	TargetHost string
	Detail     string
	CancelPath string
}

type captchaInjectedSnippetData struct {
	GenericPath  string
	ResultPath   string
	CompletePath string
}

func renderCaptchaTemplate(name string, data any) string {
	var out bytes.Buffer
	if err := captchaTemplates.ExecuteTemplate(&out, name, data); err != nil {
		log.Printf("render captcha template %s: %v", name, err)
		return ""
	}
	return out.String()
}
