/**
 * README badge URL for a project. Dashboard projects keep local ids (proj-...), which the badge endpoint
 * cannot find, so public GitHub repositories are addressed by owner/name and only saved (uuid) projects by id.
 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GITHUB_REPO = /^(?:https?:\/\/github\.com\/)?([\w.-]+\/[\w.-]+?)(?:\.git)?\/?$/;

export function badgeUrlFor(project: { id?: string; repoUrl?: string } | null | undefined, appUrl: string): string | null {
  const repo = project?.repoUrl ? GITHUB_REPO.exec(project.repoUrl.trim())?.[1] : undefined;
  if (repo) return `${appUrl}/api/v1/badge?repo=${encodeURIComponent(repo).replace('%2F', '/')}`;
  if (project?.id && UUID.test(project.id)) return `${appUrl}/api/v1/badge?projectId=${encodeURIComponent(project.id)}`;
  return null;
}
