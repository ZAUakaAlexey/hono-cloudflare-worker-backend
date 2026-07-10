const HTML_TAG_REGEX = /<[^>]*>/g;

export function stripHtmlTags(input: string): string {
  return input.replace(HTML_TAG_REGEX, "");
}
