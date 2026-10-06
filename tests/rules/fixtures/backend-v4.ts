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
  {
    ruleIds: [29106], name: 'BEF-06 SpEL expression from a request parameter',
    detects: f('src/main/java/com/acme/CalcController.java', `package com.acme;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

@RestController
public class CalcController {
  private final ExpressionParser parser = new SpelExpressionParser();

  @GetMapping("/calc")
  public Object calc(@RequestParam String expr) {
    return parser.parseExpression(expr).getValue();
  }
}
`),
    ignores: f('src/main/java/com/acme/PriceRules.java', `package com.acme;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class PriceRules {
  private final ExpressionParser parser = new SpelExpressionParser();

  public Object discount(Order order) {
    return parser.parseExpression("total * 0.9").getValue(order);
  }
}
`)
  },
  {
    ruleIds: [29107], name: 'BEF-07 extract() on $_POST',
    detects: f('public/profile.php', `<?php
$is_admin = false;
extract($_POST);
if ($is_admin) { show_admin_panel(); }
`),
    ignores: f('public/profile.php', `<?php
$is_admin = current_user_is_admin();
$name = $_POST['name'] ?? '';
extract(['title' => 'Profile']);
`)
  },
  {
    ruleIds: [29109], name: 'BEF-09 Laravel orderByRaw with request input',
    detects: f('app/Http/Controllers/ProductController.php', `<?php
class ProductController extends Controller {
  public function index(Request $request) {
    return Product::query()->orderByRaw($request->input('sort') . ' DESC')->get();
  }
}
`),
    ignores: f('app/Http/Controllers/ProductController.php', `<?php
class ProductController extends Controller {
  public function index(Request $request) {
    return Product::query()->selectRaw('price * ? as total', [$request->input('rate')])->get();
  }
}
`)
  },
  {
    ruleIds: [29108], name: 'BEF-08 send_file with params path',
    detects: f('app/controllers/downloads_controller.rb', `class DownloadsController < ApplicationController
  def show
    send_file Rails.root.join("uploads", params[:file])
  end
end
`),
    ignores: f('app/controllers/downloads_controller.rb', `class DownloadsController < ApplicationController
  def show
    upload = current_user.uploads.find(params[:id])
    send_file upload.path
  end
end
`)
  },
];
