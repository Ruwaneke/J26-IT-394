/**
 * Sentinel — AI Fix Engine (Google Gemini)
 *
 * Generates a concrete, line-range code patch for a detected vulnerability
 * using Gemini, then VERIFIES it with Sentinel's own rule engine before the
 * developer is offered the "Apply" button.
 *
 * Flow:
 *   finding + surrounding code (±AI_FIX_CONTEXT_LINES, line-numbered)
 *     → Gemini (JSON-schema output: startLine / endLine / replacement / explanation)
 *     → patch applied in memory → SecurityAnalyzer re-run on the patched file
 *     → still flagged?  one repair round with the remaining finding as feedback
 *     → proposal { verified, verifyNote } returned to the dashboard
 *
 * Gemini often answers 503 "high demand": the SDK retries 408/429/5xx with
 * backoff, and if a model stays unavailable the next model in the fallback
 * chain is tried.
 *
 * Nothing is written to disk here — applying a proposal is an explicit,
 * developer-triggered action handled by extension.ts.
 */

import type * as GenAI from '@google/genai' with { 'resolution-mode': 'import' };
import * as z from 'zod/v4';
import { SecurityAnalyzer } from '../analyzer/securityAnalyzer.js';
import { SecurityFinding, owaspCategoryFor } from '../analyzer/types.js';
import { VULNERABILITY_METADATA } from '../diagnostics/vulnerabilityMetadata.js';

// @google/genai types are published as ESM; its CommonJS build is loaded at runtime
// (this extension compiles to CommonJS).
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { GoogleGenAI, ApiError } = require('@google/genai') as typeof GenAI;
type Content = GenAI.Content;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AiFixProposal {
  findingId: string;
  vulnerabilityType: string;
  fileName: string;
  /** 1-indexed, inclusive range of the ORIGINAL file that is replaced */
  startLine: number;
  endLine: number;
  originalCode: string;
  fixedCode: string;
  explanation: string;
  changes: string[];
  /** true = Sentinel no longer flags this vulnerability in the patched code */
  verified: boolean;
  verifyNote: string;
  /** Model that actually produced the patch (may be a fallback model) */
  model: string;
  attempts: number;
  generatedAt: string;
}

export type AiFixState =
  | { status: 'pending'; startedAt: string }
  | { status: 'ready'; proposal: AiFixProposal }
  | { status: 'error'; error: string }
  | { status: 'applied'; proposal: AiFixProposal; appliedAt: string };

export interface AiFixEngineOptions {
  /** Preferred Gemini model, e.g. "gemini-flash-latest" */
  model: string;
}

export class AiFixNotConfiguredError extends Error {
  constructor() {
    super('No Gemini API key configured. Run "Sentinel: Set Gemini API Key" or set GEMINI_API_KEY.');
  }
}

// ─── Constants ────────────────────────────────────────────────────────────────

/** Lines of code sent on each side of the flagged line */
export const AI_FIX_CONTEXT_LINES = 25;

/** Tried in order after the configured model when it is overloaded or unavailable */
const FALLBACK_MODELS = ['gemini-flash-latest', 'gemini-2.5-flash', 'gemini-flash-lite-latest'];

const FixSchema = z.object({
  startLine: z.number().int().describe('First line (1-indexed, from the numbered context) to replace'),
  endLine: z.number().int().describe('Last line (inclusive) to replace'),
  replacement: z.string().describe('The new code that replaces lines startLine..endLine, with the original indentation'),
  explanation: z.string().describe('2-4 sentences: why the original code was vulnerable and why the replacement is safe'),
  changes: z.array(z.string()).describe('Short bullet list of the concrete changes made'),
});
type FixOutput = z.infer<typeof FixSchema>;
const FIX_JSON_SCHEMA = z.toJSONSchema(FixSchema);

const SYSTEM_PROMPT = `You are Sentinel's secure-code repair engine, embedded in a VS Code extension.
You receive one vulnerability detected by a static rule engine, plus the surrounding source code with line numbers.
Return a minimal patch that removes the vulnerability while preserving the code's behaviour and style.

Rules for the patch:
- Replace a contiguous range of lines that lies inside the numbered context you were given. Keep the range as small as possible, but include every line you change.
- The replacement must be complete, compilable code in the same language, using the file's existing indentation. Do not include line numbers or markdown fences.
- Prefer the project's existing libraries and patterns. If a new import or dependency is unavoidable, mention it in "changes" instead of editing lines outside the context.
- Never "fix" by deleting the functionality, commenting the code out, or suppressing the warning. Fix the root cause (parameterise queries, encode output, move secrets to environment variables or a secret store, validate input, etc.).
- If the finding looks like a false positive, still return the safest equivalent code and say so in the explanation.`;

// ─── Engine ───────────────────────────────────────────────────────────────────

export class AiFixEngine {
  constructor(
    private readonly analyzer: SecurityAnalyzer,
    private readonly getApiKey: () => Promise<string | undefined>,
    private readonly log: (msg: string) => void,
  ) {}

  async generateFix(
    finding: SecurityFinding,
    documentText: string,
    languageId: string,
    opts: AiFixEngineOptions,
  ): Promise<AiFixProposal> {
    const ai = await this.createClient();
    const lines = documentText.split(/\r?\n/);
    const eol = documentText.includes('\r\n') ? '\r\n' : '\n';
    const winStart = Math.max(1, finding.lineNumber - AI_FIX_CONTEXT_LINES);
    const winEnd = Math.min(lines.length, finding.lineNumber + AI_FIX_CONTEXT_LINES);
    const numbered = lines.slice(winStart - 1, winEnd)
      .map((l, i) => `${String(winStart + i).padStart(5)} | ${l}`).join('\n');

    const meta = VULNERABILITY_METADATA[finding.type];
    const owasp = owaspCategoryFor(finding.type);
    const contents: Content[] = [{
      role: 'user',
      parts: [{
        text:
          `File: ${finding.fileName.replace(/\\/g, '/').split('/').pop()} (language: ${languageId})\n` +
          `Vulnerability: ${meta?.title ?? finding.type} [${finding.type}]${owasp ? ` — OWASP ${owasp.id} ${owasp.name}` : ''}\n` +
          `Severity: ${finding.severity} · Rule: ${finding.detectedByRule} · Line ${finding.lineNumber}\n` +
          `Detector message: ${finding.message}\n` +
          `Flagged code: ${finding.codeSnippet.trim()}\n` +
          (meta?.recommendation ? `Guidance: ${meta.recommendation.replace(/\*\*/g, '')}\n` : '') +
          `\nNumbered context (lines ${winStart}-${winEnd}):\n${numbered}`,
      }],
    }];

    const models = [...new Set([opts.model, ...FALLBACK_MODELS].filter(Boolean))];
    let model = models[0];
    let attempts = 0;
    let last: { out: FixOutput; verified: boolean; note: string; fixedCode: string; start: number; end: number } | undefined;

    while (attempts < 2) {
      attempts++;
      const res = await this.callWithFallback(ai, models.slice(models.indexOf(model)), contents);
      model = res.model;
      const { out, modelContent } = res;

      const start = Math.max(winStart, Math.min(out.startLine, out.endLine));
      const end = Math.min(winEnd, Math.max(out.startLine, out.endLine));
      const fixedCode = out.replacement.replace(/\r?\n/g, eol).replace(/(\r?\n)+$/, '');
      const check = this.verify(finding, lines, start, end, fixedCode, languageId, eol);
      last = { out, verified: check.verified, note: check.note, fixedCode, start, end };
      this.log(`[AI Fix] ${finding.type} @ line ${finding.lineNumber}: attempt ${attempts} (${model}) → ${check.verified ? 'verified' : 'not verified'} (${check.note})`);

      if (check.verified) { break; }
      // One repair round: feed the rule engine's verdict back to the model.
      // The model turn is passed back as-is so its thought signatures are preserved.
      contents.push(
        modelContent,
        { role: 'user', parts: [{ text: `Sentinel re-scanned your patched code and it is NOT fixed yet: ${check.note}\nReturn a corrected patch for the same numbered context.` }] },
      );
    }

    const r = last!;
    return {
      findingId: finding.id,
      vulnerabilityType: finding.type,
      fileName: finding.fileName,
      startLine: r.start,
      endLine: r.end,
      originalCode: lines.slice(r.start - 1, r.end).join(eol),
      fixedCode: r.fixedCode,
      explanation: r.out.explanation,
      changes: r.out.changes,
      verified: r.verified,
      verifyNote: r.note,
      model,
      attempts,
      generatedAt: new Date().toISOString(),
    };
  }

  /** Calls Gemini, moving down the model chain while a model is overloaded / unavailable. */
  private async callWithFallback(
    ai: GenAI.GoogleGenAI, models: string[], contents: Content[],
  ): Promise<{ out: FixOutput; modelContent: Content; model: string }> {
    let lastErr: unknown;
    for (const model of models) {
      try {
        const response = await ai.models.generateContent({
          model,
          contents,
          config: {
            systemInstruction: SYSTEM_PROMPT,
            responseMimeType: 'application/json',
            responseJsonSchema: FIX_JSON_SCHEMA,
            maxOutputTokens: 16000,
          },
        });

        const blocked = response.promptFeedback?.blockReason;
        if (blocked) { throw new Error(`Gemini blocked this request (${blocked}).`); }
        const cand = response.candidates?.[0];
        const finish = cand?.finishReason;
        if (finish === 'MAX_TOKENS') { throw new Error('The AI response was cut off before the fix was complete.'); }
        if (finish && finish !== 'STOP') { throw new Error(`Gemini stopped without a fix (${finish}).`); }

        let parsed: unknown;
        try { parsed = JSON.parse(response.text ?? ''); } catch { parsed = undefined; }
        const out = FixSchema.safeParse(parsed);
        if (!out.success) { throw new Error('The AI response could not be parsed as a fix.'); }
        return { out: out.data, modelContent: cand?.content ?? { role: 'model', parts: [{ text: response.text ?? '' }] }, model };
      } catch (err) {
        lastErr = err;
        // Only overload / unknown-model errors move on to the next model; everything else is final
        if (err instanceof ApiError && [404, 429, 500, 503, 504].includes(err.status)) {
          this.log(`[AI Fix] ${model} unavailable (${err.status}) — trying next model.`);
          continue;
        }
        throw err;
      }
    }
    throw lastErr;
  }

  /** Re-runs every Sentinel rule on the patched file and checks the patched region. */
  private verify(
    finding: SecurityFinding, lines: string[], start: number, end: number,
    fixedCode: string, languageId: string, eol: string,
  ): { verified: boolean; note: string } {
    const newLines = fixedCode.split(/\r?\n/);
    const patched = [...lines.slice(0, start - 1), ...newLines, ...lines.slice(end)].join(eol);
    const regionEnd = start + newLines.length - 1;
    const inRegion = this.analyzer.analyze(patched, finding.fileName, languageId)
      .filter(f => f.lineNumber >= start - 1 && f.lineNumber <= regionEnd + 1);
    const same = inRegion.filter(f => f.type === finding.type);
    if (same.length) {
      return { verified: false, note: `${finding.type} is still detected at line ${same[0].lineNumber}: ${same[0].message}` };
    }
    if (inRegion.length) {
      const f = inRegion[0];
      return { verified: false, note: `the patch introduces ${f.type} at line ${f.lineNumber}: ${f.message}` };
    }
    return { verified: true, note: 'Sentinel re-scanned the patched code — no vulnerabilities remain in the changed lines.' };
  }

  private async createClient(): Promise<GenAI.GoogleGenAI> {
    const apiKey = (await this.getApiKey()) || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    if (!apiKey) { throw new AiFixNotConfiguredError(); }
    return new GoogleGenAI({
      apiKey,
      // Retry transient overload (5xx) with backoff (delays in seconds). 429 = quota exhausted
      // for that model, so it is not retried — callWithFallback moves straight to the next model.
      httpOptions: { retryOptions: { attempts: 3, initialDelay: 1.5, maxDelay: 8, httpStatusCodes: [408, 500, 502, 503, 504] } },
    });
  }
}

/** Human-readable message for SDK / engine errors shown on the dashboard. */
export function describeAiFixError(err: unknown): string {
  if (err instanceof AiFixNotConfiguredError) { return err.message; }
  if (err instanceof ApiError) {
    switch (err.status) {
      case 400: return /api key/i.test(err.message)
        ? 'Gemini rejected the API key. Run "Sentinel: Set Gemini API Key" to update it.'
        : `Gemini rejected the request: ${err.message}`;
      case 401:
      case 403: return 'Gemini rejected the API key, or it is not allowed to use this model. Run "Sentinel: Set Gemini API Key" to update it.';
      case 404: return 'The configured Gemini model was not found. Check the "sentinel.aiFix.model" setting.';
      case 429: return 'Gemini quota or rate limit reached — try again in a moment.';
      case 500:
      case 503:
      case 504: return 'Gemini is overloaded right now (high demand). Try again in a moment.';
      default: return `Gemini API error ${err.status}: ${err.message}`;
    }
  }
  if (err instanceof TypeError && /fetch/i.test(err.message)) { return 'Could not reach the Gemini API. Check your network connection.'; }
  return err instanceof Error ? err.message : String(err);
}
