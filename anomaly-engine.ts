
export type AnomalyMethod = "zscore" | "iqr" | "modified-zscore";

export interface AnomalyResult {
  index: number;
  value: number;
  score: number;
  method: AnomalyMethod;
  isAnomaly: boolean;
  severity: "normal" | "low" | "medium" | "high" | "critical";
}

export interface DetectionOptions {
  method?: AnomalyMethod;
  threshold?: number;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);

  return sorted.length % 2
    ? sorted[mid]!
    : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

function percentile(values: number[], p: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  const pos = (sorted.length - 1) * p;
  const low = Math.floor(pos);
  const high = Math.ceil(pos);

  return sorted[low]! +
    (sorted[high]! - sorted[low]!) * (pos - low);
}

function severity(score: number, threshold: number): AnomalyResult["severity"] {
  if (score < threshold) return "normal";
  if (score >= threshold * 2.5) return "critical";
  if (score >= threshold * 2) return "high";
  if (score >= threshold * 1.5) return "medium";
  return "low";
}

export function detectAnomalies(
  values: number[],
  options: DetectionOptions = {}
): AnomalyResult[] {
  const { method = "zscore", threshold = 3 } = options;

  if (values.length < 4) throw new Error("Minimum 4 values required.");
  if (!Number.isFinite(threshold) || threshold <= 0)
    throw new Error("Invalid threshold.");
  if (!values.every(Number.isFinite))
    throw new Error("Values must be finite numbers.");

  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const std = Math.sqrt(values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length);
  const med = median(values);
  const mad = median(values.map(v => Math.abs(v - med)));
  const q1 = percentile(values, 0.25);
  const q3 = percentile(values, 0.75);
  const iqr = q3 - q1;

  return values.map((value, index) => {
    let score = 0;
    let isAnomaly = false;

    switch (method) {
      case "zscore":
        score = std === 0 ? 0 : Math.abs((value - mean) / std);
        isAnomaly = score >= threshold;
        break;

      case "modified-zscore":
        score = mad === 0 ? (value === med ? 0 : Infinity)
          : 0.67448975 * Math.abs(value - med) / mad;
        isAnomaly = score >= threshold;
        break;

      case "iqr": {
        const lower = q1 - 1.5 * iqr;
        const upper = q3 + 1.5 * iqr;
        const distance = value < lower ? lower - value
          : value > upper ? value - upper : 0;

        score = iqr === 0 ? (distance > 0 ? Infinity : 0) : distance / iqr;
        isAnomaly = distance > 0;
        break;
      }

      default:
        throw new Error("Unsupported method.");
    }

    return {
      index,
      value,
      score,
      method,
      isAnomaly,
      severity: severity(score, threshold),
    };
  });
}

// ANOMALY SUMMARY

export function getAnomalySummary(results: AnomalyResult[]) {
  const anomalies = results.filter(r => r.isAnomaly);

  return {
    total: results.length,
    anomalyCount: anomalies.length,
    normalCount: results.length - anomalies.length,
    anomalyIndexes: anomalies.map(r => r.index),
  };
}

// JSON INSPECTOR

export function inspectJson(
  input: string,
  options: DetectionOptions = {}
) {
  const data: unknown = JSON.parse(input);
  const numbers: { path: string; value: number }[] = [];
  const issues: { path: string; type: string; value?: unknown }[] = [];

  function walk(value: unknown, path: string): void {
    if (value === null) {
      issues.push({ path, type: "null" });
    } else if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, `${path}[${i}]`));
    } else if (typeof value === "object") {
      Object.entries(value).forEach(([key, v]) => {
        walk(v, `${path}.${key}`);
      });
    } else if (typeof value === "number") {
      numbers.push({ path, value });
    } else if (typeof value === "string" && !value.trim()) {
      issues.push({ path, type: "empty" });
    }
  }

  walk(data, "$");

  const groups = new Map<string, typeof numbers>();

  numbers.forEach(item => {
    const key = item.path.split(".").pop()!.split("[")[0] ?? "unknown";
    const group = groups.get(key) ?? [];
    group.push(item);
    groups.set(key, group);
  });

  const anomalies: { path: string; result: AnomalyResult }[] = [];

  for (const group of groups.values()) {
    if (group.length < 4) continue;

    detectAnomalies(group.map(x => x.value), options)
      .filter(r => r.isAnomaly)
      .forEach(r => {
        const item = group[r.index]!;
        anomalies.push({ path: item.path, result: r });
        issues.push({ path: item.path, type: "anomaly", value: item.value });
      });
  }

  return {
    isValid: true,
    totalNumbers: numbers.length,
    totalIssues: issues.length,
    anomalyCount: anomalies.length,
    anomalyIndexes: anomalies.map(a => a.result.index),
    issues,
    anomalies,
  };
}
