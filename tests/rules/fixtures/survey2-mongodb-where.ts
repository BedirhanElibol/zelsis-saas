import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [3020], name: 'INFRA-20 MongoDB $where JavaScript evaluation vs GraphQL $where variable declarations',
    detects: [
      ...f('server/routes/users.ts', `export async function searchUsers(req: any, db: any) {
  return db.users.find({ $where: \`this.name == '\${req.query.name}'\` });
}
`),
    ],
    ignores: [
      ...f('src/graphql/blueprints.ts', `import { gql } from '@apollo/client';

export const DELETE_BLUEPRINT = gql\`
  mutation deleteBlueprint($where: WhereUniqueInput!) {
    deleteBlueprint(where: $where) { id }
  }
\`;
`),
      ...f('src/graphql/hasura.ts', `export const buildSubscription = (operation: string, hasuraFiltersType: string) => \`
  subscription \${operation}($where: \${hasuraFiltersType}) {
    items(where: $where) { id }
  }
\`;

export const USERS_QUERY = "query ($where: users_bool_exp) { users(where: $where) { id } }";
`),
    ],
  },
];
