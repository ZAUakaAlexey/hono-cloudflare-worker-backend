const HTML_TAG_REGEX = /<[^>]*>/g;
const UTF7_PATTERN = /\+[A-Za-z0-9/]+-?/g;
const NULL_BYTE_REGEX = /\x00/g;

export function stripHtmlTags(input: string): string {
  return input
    .replace(NULL_BYTE_REGEX, "")
    .replace(UTF7_PATTERN, "")
    .replace(HTML_TAG_REGEX, "")
    .trim();
}

export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}
