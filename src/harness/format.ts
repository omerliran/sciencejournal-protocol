import { revealHidden } from "../scan";

// How the harness writes things for people and agents to read.

export function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

export function size(bytes: number): string {
  if (bytes < 1024) return plural(bytes, "byte");
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function seconds(value: number): string {
  if (value < 10) return `${value.toFixed(2)} s`;
  if (value < 60) return `${value.toFixed(1)} s`;
  const whole = Math.round(value);
  return `${Math.floor(whole / 60)} min ${whole % 60} s`;
}

/** Text from a bundle as inline Markdown code, with anything hidden in it made visible. */
export function code(text: string): string {
  const shown = revealHidden(text).replaceAll("|", "\\|");
  return shown.includes("`") ? `\`\` ${shown} \`\`` : `\`${shown}\``;
}

/** A value as JSON, cut short, with anything hidden in it made visible. */
export function shown(value: unknown, max = 60): string {
  const text = revealHidden(JSON.stringify(value) ?? "nothing");
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** Text as one shell word. */
export function shellQuote(text: string): string {
  return /^[\w@%+=:,./-]+$/.test(text) ? text : `'${text.replaceAll("'", "'\"'\"'")}'`;
}
