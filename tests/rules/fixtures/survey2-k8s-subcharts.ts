import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [8901, 15701], name: 'K8S-01 / KERN-SEC-01 privileged: true on app deployment vs vendored Helm subcharts',
    detects: f('charts/myapp/templates/deployment.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-worker
spec:
  template:
    spec:
      containers:
        - name: worker
          image: ghcr.io/acme/worker:1.4.2
          securityContext:
            privileged: true
`),
    ignores: [
      ...f('deploy/charts/openebs/charts/openebs-ndm/templates/node-exporter.yaml', `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: openebs-ndm
spec:
  template:
    spec:
      containers:
        - name: ndm
          image: openebs/node-disk-manager:2.1.0
          securityContext:
            privileged: true
`),
      ...f('deploy/k8s/psp.yaml', `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged-psp
spec:
  privileged: true
`),
    ],
  },
  {
    ruleIds: [8312], name: 'IAC-12 hostPID/hostIPC on app manifest vs PodSecurityPolicy and vendored Helm subcharts',
    detects: f('deploy/k8s/worker.yaml', `apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: worker
          image: ghcr.io/acme/worker:1.4.2
`),
    ignores: [
      ...f('charts/monitoring/charts/prometheus/templates/node-exporter-daemonset.yaml', `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-exporter
spec:
  template:
    spec:
      hostPID: true
      hostIPC: true
`),
      ...f('deploy/k8s/psp.yaml', `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted-psp
spec:
  hostPID: true
  hostIPC: true
`),
    ],
  },
];
