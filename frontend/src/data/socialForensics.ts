// Static reference + link-builder data for the Social Forensics module. Every
// resource here is a URL TEMPLATE — the operator's own browser opens the link;
// the backend never queries these sites. This keeps people-OSINT passive (public
// profiles + search engines + breach-lookup front-ends) and dependency-free.
// For AUTHORIZED engagement reconnaissance only.

export type SelectorType = 'username' | 'email' | 'name' | 'phone'

export const SELECTOR_LABELS: Record<SelectorType, string> = {
  username: 'Username',
  email: 'Email',
  name: 'Full name',
  phone: 'Phone',
}

export type ResourceCategory =
  | 'Social'
  | 'Professional'
  | 'Developer'
  | 'Media & video'
  | 'Messaging'
  | 'Gaming'
  | 'Search dork'
  | 'Breach & exposure'
  | 'Reverse & metadata'

export interface Resource {
  id: string
  name: string
  category: ResourceCategory
  // {q} is replaced with the encodeURIComponent-encoded selector value.
  url: string
  types: SelectorType[]
  note?: string
}

// Build a live URL from a resource template + the operator's input.
export function buildUrl(template: string, value: string): string {
  return template.replace(/\{q\}/g, encodeURIComponent(value.trim()))
}

export const RESOURCES: Resource[] = [
  // ---- Social ----
  { id: 'twitter', name: 'X / Twitter', category: 'Social', url: 'https://x.com/{q}', types: ['username'] },
  { id: 'instagram', name: 'Instagram', category: 'Social', url: 'https://www.instagram.com/{q}/', types: ['username'] },
  { id: 'tiktok', name: 'TikTok', category: 'Social', url: 'https://www.tiktok.com/@{q}', types: ['username'] },
  { id: 'facebook', name: 'Facebook', category: 'Social', url: 'https://www.facebook.com/{q}', types: ['username'] },
  { id: 'reddit', name: 'Reddit', category: 'Social', url: 'https://www.reddit.com/user/{q}', types: ['username'] },
  { id: 'pinterest', name: 'Pinterest', category: 'Social', url: 'https://www.pinterest.com/{q}/', types: ['username'] },
  { id: 'threads', name: 'Threads', category: 'Social', url: 'https://www.threads.net/@{q}', types: ['username'] },
  { id: 'mastodon', name: 'Mastodon (search)', category: 'Social', url: 'https://mastodon.social/search?q={q}', types: ['username'] },
  { id: 'bluesky', name: 'Bluesky', category: 'Social', url: 'https://bsky.app/profile/{q}', types: ['username'] },
  { id: 'vk', name: 'VK', category: 'Social', url: 'https://vk.com/{q}', types: ['username'] },

  // ---- Professional ----
  { id: 'linkedin', name: 'LinkedIn (profile)', category: 'Professional', url: 'https://www.linkedin.com/in/{q}', types: ['username'] },
  { id: 'linkedin-search', name: 'LinkedIn (people search)', category: 'Professional', url: 'https://www.linkedin.com/search/results/people/?keywords={q}', types: ['name'] },
  { id: 'angellist', name: 'Wellfound (AngelList)', category: 'Professional', url: 'https://wellfound.com/u/{q}', types: ['username'] },
  { id: 'about-me', name: 'About.me', category: 'Professional', url: 'https://about.me/{q}', types: ['username'] },

  // ---- Developer ----
  { id: 'github', name: 'GitHub', category: 'Developer', url: 'https://github.com/{q}', types: ['username'] },
  { id: 'gitlab', name: 'GitLab', category: 'Developer', url: 'https://gitlab.com/{q}', types: ['username'] },
  { id: 'github-email', name: 'GitHub (commits by email)', category: 'Developer', url: 'https://github.com/search?q=author-email%3A{q}&type=commits', types: ['email'], note: 'Finds commits authored with this email.' },
  { id: 'keybase', name: 'Keybase', category: 'Developer', url: 'https://keybase.io/{q}', types: ['username'] },
  { id: 'stackoverflow', name: 'Stack Overflow (search)', category: 'Developer', url: 'https://stackoverflow.com/users?q={q}', types: ['username', 'name'] },
  { id: 'dockerhub', name: 'Docker Hub', category: 'Developer', url: 'https://hub.docker.com/u/{q}', types: ['username'] },
  { id: 'npm', name: 'npm', category: 'Developer', url: 'https://www.npmjs.com/~{q}', types: ['username'] },
  { id: 'hackernews', name: 'Hacker News', category: 'Developer', url: 'https://news.ycombinator.com/user?id={q}', types: ['username'] },

  // ---- Media & video ----
  { id: 'youtube', name: 'YouTube', category: 'Media & video', url: 'https://www.youtube.com/@{q}', types: ['username'] },
  { id: 'twitch', name: 'Twitch', category: 'Media & video', url: 'https://www.twitch.tv/{q}', types: ['username'] },
  { id: 'medium', name: 'Medium', category: 'Media & video', url: 'https://medium.com/@{q}', types: ['username'] },
  { id: 'soundcloud', name: 'SoundCloud', category: 'Media & video', url: 'https://soundcloud.com/{q}', types: ['username'] },
  { id: 'spotify', name: 'Spotify (search)', category: 'Media & video', url: 'https://open.spotify.com/search/{q}', types: ['username', 'name'] },
  { id: 'flickr', name: 'Flickr', category: 'Media & video', url: 'https://www.flickr.com/people/{q}', types: ['username'] },

  // ---- Messaging ----
  { id: 'telegram', name: 'Telegram', category: 'Messaging', url: 'https://t.me/{q}', types: ['username'] },
  { id: 'snapchat', name: 'Snapchat', category: 'Messaging', url: 'https://www.snapchat.com/add/{q}', types: ['username'] },

  // ---- Gaming ----
  { id: 'steam', name: 'Steam', category: 'Gaming', url: 'https://steamcommunity.com/id/{q}', types: ['username'] },
  { id: 'xbox', name: 'Xbox (XboxGamertag)', category: 'Gaming', url: 'https://xboxgamertag.com/search/{q}', types: ['username'] },
  { id: 'roblox', name: 'Roblox (search)', category: 'Gaming', url: 'https://www.roblox.com/search/users?keyword={q}', types: ['username'] },

  // ---- Search dorks ----
  { id: 'g-exact', name: 'Google — exact match', category: 'Search dork', url: 'https://www.google.com/search?q=%22{q}%22', types: ['username', 'email', 'name', 'phone'] },
  { id: 'g-social', name: 'Google — across social sites', category: 'Search dork', url: 'https://www.google.com/search?q=%22{q}%22+(site%3Atwitter.com+OR+site%3Ainstagram.com+OR+site%3Afacebook.com+OR+site%3Alinkedin.com+OR+site%3Atiktok.com)', types: ['username', 'name'] },
  { id: 'g-pastes', name: 'Google — paste sites', category: 'Search dork', url: 'https://www.google.com/search?q=%22{q}%22+(site%3Apastebin.com+OR+site%3Aghostbin.com+OR+site%3Acontrolc.com)', types: ['username', 'email'] },
  { id: 'g-docs', name: 'Google — documents (CV/resume)', category: 'Search dork', url: 'https://www.google.com/search?q=%22{q}%22+(filetype%3Apdf+OR+filetype%3Adocx)+(resume+OR+cv)', types: ['name', 'email'] },
  { id: 'g-email-user', name: 'Google — email as username', category: 'Search dork', url: 'https://www.google.com/search?q=%22{q}%22', types: ['email'], note: 'Reused handle: try the local-part of the email as a username too.' },
  { id: 'bing-exact', name: 'Bing — exact match', category: 'Search dork', url: 'https://www.bing.com/search?q=%22{q}%22', types: ['username', 'email', 'name', 'phone'] },
  { id: 'duck-exact', name: 'DuckDuckGo — exact match', category: 'Search dork', url: 'https://duckduckgo.com/?q=%22{q}%22', types: ['username', 'email', 'name', 'phone'] },

  // ---- Breach & exposure (lookup front-ends) ----
  { id: 'hibp', name: 'Have I Been Pwned', category: 'Breach & exposure', url: 'https://haveibeenpwned.com/', types: ['email'], note: 'Paste the email into HIBP — breach exposure of this address.' },
  { id: 'dehashed', name: 'DeHashed (search)', category: 'Breach & exposure', url: 'https://dehashed.com/search?query={q}', types: ['email', 'username', 'name', 'phone'] },
  { id: 'intelx', name: 'Intelligence X', category: 'Breach & exposure', url: 'https://intelx.io/?s={q}', types: ['email', 'username', 'phone'] },
  { id: 'snusbase', name: 'Snusbase', category: 'Breach & exposure', url: 'https://snusbase.com/', types: ['email', 'username'], note: 'Search the selector in Snusbase’s breach index.' },
  { id: 'hunter', name: 'Hunter.io (email → org)', category: 'Breach & exposure', url: 'https://hunter.io/email-finder', types: ['email', 'name'] },

  // ---- Reverse & metadata ----
  { id: 'gravatar', name: 'Gravatar (profile by email)', category: 'Reverse & metadata', url: 'https://gravatar.com/', types: ['email'], note: 'Gravatar profile is keyed on the MD5 of the email — check via a Gravatar lookup tool.' },
  { id: 'epieos', name: 'Epieos (email/phone lookup)', category: 'Reverse & metadata', url: 'https://epieos.com/', types: ['email', 'phone'] },
  { id: 'truecaller', name: 'Truecaller (phone)', category: 'Reverse & metadata', url: 'https://www.truecaller.com/search/global/{q}', types: ['phone'] },
  { id: 'g-images', name: 'Google Images (reverse — paste an image URL)', category: 'Reverse & metadata', url: 'https://images.google.com/', types: ['username', 'name'], note: 'Reverse-search a profile avatar to correlate accounts.' },
]

export interface MethodologyPhase {
  phase: string
  goal: string
  steps: string[]
  tips: string[]
}

// A repeatable people-OSINT workflow: seed → enumerate → pivot → deepen → verify.
export const METHODOLOGY: MethodologyPhase[] = [
  {
    phase: '1 · Seed & scope',
    goal: 'Fix the authorized target and the selectors you start from.',
    steps: [
      'Confirm the person/persona is in scope and that people-OSINT is authorized for this engagement.',
      'Collect seed selectors: full name, known usernames/handles, email(s), phone, employer.',
      'Decide the objective (pretext research, exposure assessment, attack-surface) — it shapes what matters.',
    ],
    tips: [
      'Record every source with a timestamp from the start — attribution matters in the report.',
      'Keep raw selectors and derived ones (e.g. email local-part reused as a handle) separate.',
    ],
  },
  {
    phase: '2 · Enumerate presence',
    goal: 'Map where the selector exists across platforms.',
    steps: [
      'Run the username across social/dev/media platforms (the Pivot tab does this in one click).',
      'Pivot the email: breach front-ends, GitHub commit-email search, Gravatar, org email-finders.',
      'Use exact-match search dorks for the name/handle across social + paste + document sites.',
    ],
    tips: [
      'A hit is not identity — many people share a handle. Note candidates, don’t conclude yet.',
      'Try handle variants: dots, underscores, numbers, and the email local-part.',
    ],
  },
  {
    phase: '3 · Pivot & correlate',
    goal: 'Link candidate accounts to one identity with corroborating signals.',
    steps: [
      'Correlate avatars (reverse-image), bios, linked URLs, and cross-posted content between accounts.',
      'Follow outbound links each profile advertises (personal site, linktree, other handles).',
      'Build an identity graph: selector → accounts → shared attributes.',
    ],
    tips: [
      'Reused profile photos and identical bios are strong linkers; matching join-dates/locations help.',
      'The Canvas page is handy for sketching the identity graph as you correlate.',
    ],
  },
  {
    phase: '4 · Deepen',
    goal: 'Extract more from confirmed accounts and public records.',
    steps: [
      'Check breach/paste exposure for leaked credentials or additional selectors (emails, phones).',
      'Pull metadata from public artifacts (document authors, EXIF on downloadable images).',
      'Review archived versions (Wayback) of deleted/changed profiles and pages.',
    ],
    tips: [
      'Breach data is for exposure assessment — never use recovered credentials outside explicit auth.',
      'People delete; archives remember. Old handles and bios often reveal new selectors.',
    ],
  },
  {
    phase: '5 · Verify & document',
    goal: 'Separate confirmed facts from guesses and write it up defensibly.',
    steps: [
      'Down-rank single-source claims; require corroboration before asserting identity.',
      'Capture screenshots + URLs + timestamps for each confirmed finding.',
      'Summarise the exposure and its relevance to the engagement objective.',
    ],
    tips: [
      'Explicitly flag confidence (confirmed / probable / possible) on every linkage.',
      'Prune false positives — a wrong attribution is worse than a missing one.',
    ],
  },
]
