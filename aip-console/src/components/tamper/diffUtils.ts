/**
/**
 * Line-by-line diff utility for comparing original JSON and mutated JSON
 */

export interface DiffLine {
  type: "added" | "deleted" | "unchanged";
  originalLineNumber?: number;
  mutatedLineNumber?: number;
  content: string;
}

export interface DiffSummary {
  lines: DiffLine[];
  additions: number;
  deletions: number;
  hasChanges: boolean;
}

/**
 * Computes a line-by-line diff between two strings using the LCS algorithm.
 */
export function computeLineDiff(originalText: string, mutatedText: string): DiffSummary {
  const origLines = originalText ? originalText.split(/\r?\n/) : [];
  const mutLines = mutatedText ? mutatedText.split(/\r?\n/) : [];

  const m = origLines.length;
  const n = mutLines.length;

  // If identical
  if (originalText === mutatedText) {
    return {
      lines: origLines.map((line, idx) => ({
        type: "unchanged",
        originalLineNumber: idx + 1,
        mutatedLineNumber: idx + 1,
        content: line,
      })),
      additions: 0,
      deletions: 0,
      hasChanges: false,
    };
  }

  // LCS Matrix
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i < m; i++) {
    for (let j = 0; j < n; j++) {
      if (origLines[i] === mutLines[j]) {
        dp[i + 1][j + 1] = dp[i][j] + 1;
      } else {
        dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  // Backtrack to build diff lines
  let i = m;
  let j = n;
  const reversedDiff: DiffLine[] = [];
  let additions = 0;
  let deletions = 0;

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && origLines[i - 1] === mutLines[j - 1]) {
      reversedDiff.push({
        type: "unchanged",
        originalLineNumber: i,
        mutatedLineNumber: j,
        content: origLines[i - 1],
      });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      reversedDiff.push({
        type: "added",
        mutatedLineNumber: j,
        content: mutLines[j - 1],
      });
      additions++;
      j--;
    } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
      reversedDiff.push({
        type: "deleted",
        originalLineNumber: i,
        content: origLines[i - 1],
      });
      deletions++;
      i--;
    }
  }

  const lines = reversedDiff.reverse();

  return {
    lines,
    additions,
    deletions,
    hasChanges: additions > 0 || deletions > 0,
  };
}
