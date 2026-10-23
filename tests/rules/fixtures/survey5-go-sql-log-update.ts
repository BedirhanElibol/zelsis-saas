import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [9002],
    name: 'GO-02 SQL Injection via fmt.Sprintf vs logger calls containing status words',
    detects: f('controllers/user_controller.go', `package controllers
import (
    "database/sql"
    "fmt"
    "net/http"
)
func UpdateUser(db *sql.DB, r *http.Request) error {
    id := r.URL.Query().Get("id")
    query := fmt.Sprintf("UPDATE users SET active = true WHERE id = '%s'", id)
    _, err := db.Exec(query)
    return err
}
`),
    ignores: f('controllers/microservice_controller.go', `package controllers
import (
    "fmt"
    log "github.com/sirupsen/logrus"
)
type Microservice struct {
    Name string
}
func Reconcile(m *Microservice) {
    log.Info(fmt.Sprintf("update microservice %s status to active", m.Name))
    fmt.Println(fmt.Sprintf("update microservice %s completed", m.Name))
}
`),
  },
];
