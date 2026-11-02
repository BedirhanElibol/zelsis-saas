import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildIssue, creatableTypes, normalizeJiraSite } from '../../lib/jira';
import { integrationKey, open, seal } from '../../lib/secret-box';
import { JiraIssueSchema } from '../../lib/validations/api-schemas';
import { hasIntegrationAccess } from '../../lib/subscription-utils';

test('Jira is a paid-plan feature', () => {
  assert.equal(hasIntegrationAccess('Free'), false);
  assert.equal(hasIntegrationAccess(null), false);
  assert.equal(hasIntegrationAccess('Pro'), true);
  assert.equal(hasIntegrationAccess('Enterprise'), true);
});

test('normalizeJiraSite accepts Jira Cloud only', () => {
  assert.equal(normalizeJiraSite('acme'), 'https://acme.atlassian.net');
  assert.equal(normalizeJiraSite('https://Acme.atlassian.net/jira/software/projects'), 'https://acme.atlassian.net');
  for (const bad of ['http://169.254.169.254', 'acme.atlassian.net.evil.com', 'localhost:3000', 'evil.com/acme.atlassian.net', '']) {
    assert.equal(normalizeJiraSite(bad), null, bad);
  }
});

test('seal and open round-trip and reject tampering or the wrong key', () => {
  const key = crypto.randomBytes(32);
  const sealed = seal('atl-token', key);
  assert.ok(!sealed.includes('atl-token'));
  assert.equal(open(sealed, key), 'atl-token');
  assert.equal(open(sealed, crypto.randomBytes(32)), null);
  const parts = sealed.split('.');
  parts[3] = Buffer.from('other').toString('base64url');
  assert.equal(open(parts.join('.'), key), null);
});

test('integrationKey needs exactly 32 bytes', () => {
  assert.equal(integrationKey(undefined), null);
  assert.equal(integrationKey(Buffer.alloc(16).toString('base64')), null);
  assert.equal(integrationKey(crypto.randomBytes(32).toString('base64'))?.length, 32);
});

test('buildIssue fills project, type, summary and a document description', () => {
  const issue = buildIssue({ title: 'SQL Injection', severity: 'HIGH', filePath: 'a.ts', lineRange: 'L3', remediationPrompt: 'Use parameters', cweId: 'CWE-89' }, { projectKey: 'SEC', issueType: 'Bug' });
  assert.deepEqual(issue.fields.project, { key: 'SEC' });
  assert.deepEqual(issue.fields.issuetype, { name: 'Bug' });
  assert.equal(issue.fields.summary, '[HIGH] SQL Injection');
  assert.equal(issue.fields.description.type, 'doc');
  assert.match(JSON.stringify(issue.fields.description), /CWE-89.*a\.ts \(L3\).*Use parameters/);
});

test('creatableTypes keeps standard types in Jira order, without sub-tasks or epics', () => {
  const types = creatableTypes([
    { id: '10001', name: 'Epik', hierarchyLevel: 1 },
    { id: '10002', name: 'Subtask', subtask: true, hierarchyLevel: -1 },
    { id: '10003', name: 'Görev', hierarchyLevel: 0 },
    { id: '10004', name: 'Hikaye', hierarchyLevel: 0 },
  ]);
  assert.deepEqual(types, [{ id: '10003', name: 'Görev' }, { id: '10004', name: 'Hikaye' }]);
});

test('buildIssue sends a stored id as id and an older stored name as name', () => {
  const finding = { title: 't', severity: 'LOW' };
  assert.deepEqual(buildIssue(finding, { projectKey: 'KAN', issueType: '10003' }).fields.issuetype, { id: '10003' });
  assert.deepEqual(buildIssue(finding, { projectKey: 'KAN', issueType: 'Görev' }).fields.issuetype, { name: 'Görev' });
});

test('JiraIssueSchema rejects an odd CWE value', () => {
  const base = { accessToken: 'x'.repeat(30), title: 't', severity: 'LOW' };
  assert.ok(JiraIssueSchema.safeParse({ ...base, cweId: '' }).success);
  assert.ok(!JiraIssueSchema.safeParse({ ...base, cweId: '<script>' }).success);
});
