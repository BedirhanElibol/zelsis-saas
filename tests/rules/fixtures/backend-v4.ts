import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29101], name: 'BEF-01 Jackson default typing enabled',
    detects: f('src/main/java/com/acme/config/JsonConfig.java', `package com.acme.config;
import com.fasterxml.jackson.databind.ObjectMapper;
public class JsonConfig {
  public ObjectMapper mapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.enableDefaultTyping();
    return mapper;
  }
}
`),
    ignores: f('src/main/java/com/acme/config/JsonConfig.java', `package com.acme.config;
import com.fasterxml.jackson.databind.ObjectMapper;
public class JsonConfig {
  public ObjectMapper mapper() {
    return new ObjectMapper();
  }
}
`)
  },
  {
    ruleIds: [29102], name: 'BEF-02 Go text/template written to the response',
    detects: f('internal/web/profile.go', `package web

import (
	"net/http"
	"text/template"
)

var tpl = template.Must(template.New("p").Parse("<h1>Hello {{.Name}}</h1>"))

func Profile(w http.ResponseWriter, r *http.Request) {
	tpl.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
}
`),
    ignores: f('internal/web/profile.go', `package web

import (
	"html/template"
	"net/http"
)

var tpl = template.Must(template.New("p").Parse("<h1>Hello {{.Name}}</h1>"))

func Profile(w http.ResponseWriter, r *http.Request) {
	tpl.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
}
`)
  },
  {
    ruleIds: [29104], name: 'BEF-04 Blade prints request input unescaped',
    detects: f('resources/views/search.blade.php', `<h1>Results for {!! request('q') !!}</h1>
`),
    ignores: f('resources/views/search.blade.php', `<h1>Results for {{ request('q') }}</h1>
`)
  },
  {
    ruleIds: [29105], name: 'BEF-05 Rails constantize on params',
    detects: f('app/controllers/exports_controller.rb', `class ExportsController < ApplicationController
  def create
    exporter = params[:type].constantize.new(current_user)
    send_data exporter.call
  end
end
`),
    ignores: f('app/controllers/exports_controller.rb', `class ExportsController < ApplicationController
  EXPORTERS = { "pdf" => PdfExporter, "csv" => CsvExporter }.freeze

  def create
    exporter = EXPORTERS.fetch(params[:type]).new(current_user)
    send_data exporter.call
  end
end
`)
  },
];
