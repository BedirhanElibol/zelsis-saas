/**
 * Signup-free "ready for users" check of one live page: the things a visitor notices before they read a word
 * (template title, lorem ipsum, no preview image, no icon, not built for phones). Pure: the route fetches the HTML.
 */
export interface SiteReadinessItem {
  id: string;
  ok: boolean;
  title: string;
  detail: string;
}

/** Page titles that starter templates ship with. */
const TEMPLATE_TITLES = /^(?:create next app|react app|vite \+ react(?: \+ ts)?|vite app|nuxt app|sveltekit app|document|untitled|home|my app|index)$/i;

/** Attribute value, quoted or not (minified HTML drops the quotes: <html lang=en>). */
const attr = (tag: string, name: string) => {
  const m = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i').exec(tag);
  return m ? (m[1] ?? m[2] ?? m[3]) : undefined;
};
const metaContent = (html: string, key: RegExp) => {
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    if (key.test(attr(tag, 'name') ?? '') || key.test(attr(tag, 'property') ?? '')) return attr(tag, 'content') ?? '';
  }
  return null;
};

export function checkSiteReadiness(html: string, finalUrl: string, opts: { faviconFallbackOk?: boolean } = {}): SiteReadinessItem[] {
  const head = html.slice(0, 200_000);
  const title = (/<title[^>]*>([^<]*)<\/title>/i.exec(head)?.[1] ?? '').replace(/\s+/g, ' ').trim();
  const description = metaContent(head, /^description$/i);
  const ogImage = metaContent(head, /^og:image$/i);
  const viewport = metaContent(head, /^viewport$/i);
  const hasIconLink = [...head.matchAll(/<link\b[^>]*>/gi)].some((m) => /\bicon\b/i.test(attr(m[0], 'rel') ?? ''));
  const lang = !!attr(/<html\b[^>]*>/i.exec(head)?.[0] ?? '', 'lang');
  const body = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ');
  const lorem = /lorem ipsum dolor/i.test(body);
  const placeholder = /\b(?:Your (?:Company|Brand|Product|App) (?:Name|Logo)|Insert (?:Text|Title|Description) Here)\b/.exec(body)?.[0];

  return [
    { id: 'https', ok: finalUrl.startsWith('https://'), title: 'Served over HTTPS',
      detail: finalUrl.startsWith('https://') ? 'The page loads over HTTPS.' : 'Browsers mark the page "Not secure", and many visitors leave before it loads.' },
    { id: 'title', ok: !!title && !TEMPLATE_TITLES.test(title), title: 'A real page title',
      detail: !title ? 'The page has no <title>, so the browser tab and search results show the bare URL.'
        : TEMPLATE_TITLES.test(title) ? `The title is "${title}", the starter template default. The tab and search results show it.`
        : `Title: "${title}".` },
    { id: 'placeholder', ok: !lorem && !placeholder, title: 'No placeholder copy',
      detail: lorem ? 'The page contains "Lorem ipsum dolor" filler text.' : placeholder ? `The page still says "${placeholder}".` : 'No lorem ipsum or template placeholders found.' },
    { id: 'description', ok: !!description && description.trim().length >= 30, title: 'A description for search and link previews',
      detail: !description ? 'No meta description: search engines pick a random sentence from the page.' : description.trim().length < 30 ? `The description is only "${description.trim()}".` : 'Meta description is set.' },
    { id: 'og-image', ok: !!ogImage, title: 'A preview image when the link is shared',
      detail: ogImage ? 'og:image is set.' : 'No og:image: links shared on X, LinkedIn, Slack or WhatsApp show a blank card.' },
    { id: 'icon', ok: hasIconLink || !!opts.faviconFallbackOk, title: 'A site icon',
      detail: hasIconLink || opts.faviconFallbackOk ? 'The page has an icon for the browser tab.' : 'No icon: the browser tab and bookmarks show a blank page symbol.' },
    { id: 'viewport', ok: !!viewport && /width\s*=\s*device-width/i.test(viewport), title: 'Built for phones',
      detail: viewport && /width\s*=\s*device-width/i.test(viewport) ? 'The viewport is set for phones.' : 'No width=device-width viewport: phones show a zoomed-out desktop page.' },
    { id: 'lang', ok: lang, title: 'Page language declared',
      detail: lang ? 'The <html> element declares its language.' : 'No lang on <html>: screen readers may read the page in the wrong voice, and translators guess.' },
  ];
}
