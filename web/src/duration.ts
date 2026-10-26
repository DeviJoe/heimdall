export function durationSeconds(
  value: string,
  options: { min?: number; max?: number } = {},
): number {
  const min = options.min ?? 60;
  const max = options.max ?? 315360000;
  if (min === 0 && value.trim() === "0") return 0;
  const match = /^\s*(\d+)\s*([smhd])\s*$/i.exec(value);
  if (!match)
    throw new Error("Срок жизни: укажите число и s, m, h или d, например 365d");
  const seconds =
    Number(match[1]) *
    ({ s: 1, m: 60, h: 3600, d: 86400 }[match[2].toLowerCase()] || 0);
  if (!Number.isSafeInteger(seconds) || seconds < min || seconds > max)
    throw new Error(
      `Допустимый диапазон: ${formatDuration(min)}–${formatDuration(max)}`,
    );
  return seconds;
}

export function formatDuration(seconds: number): string {
  if (seconds === 0) return "0";
  for (const [unit, divisor] of [
    ["d", 86400],
    ["h", 3600],
    ["m", 60],
    ["s", 1],
  ] as const) {
    if (seconds % divisor === 0) return `${seconds / divisor}${unit}`;
  }
  return `${seconds}s`;
}
