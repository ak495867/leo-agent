/**
 * Rough upper‑bound: ~4 characters per token for typical code/text.
 */
const CHARS_PER_TOKEN = 4;

/**
 * Very rough estimate of how many tokens a text string will consume.
 * Used to enforce the 80 K token cap before sending a request.
 */
export function estimateTokenCount(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}

/**
 * Call an OpenRouter LLM with a system prompt and user content.
 * Returns the raw `content` field of the first choice (expected JSON).
 *
 * Throws on HTTP errors or unexpected response shapes.
 */
export async function callAgent(
  systemPrompt: string, userContent: string, model: string, apiKey: string
): Promise<string> {
  const combined = systemPrompt + "\n" + userContent;
  const estimatedTokens = estimateTokenCount(combined);
  if (estimatedTokens > 80_000) {
    throw new Error(`Request rejected: estimated ${estimatedTokens.toLocaleString()} tokens exceeds Leo's 80,000-token safety budget. Split the scan into smaller batches; no source was silently truncated.`);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120_000);
  try {
    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      signal: controller.signal,
      headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json", "HTTP-Referer": "https://github.com/ak495867/leo-agent", "X-Title": "Leo Security Agent" },
      body: JSON.stringify({ model, temperature: 0.1, response_format: { type: "json_object" }, messages: [
        { role: "system", content: systemPrompt }, { role: "user", content: userContent }
      ] })
    });
    if (!response.ok) {
      const txt = (await response.text()).slice(0, 2000);
      throw new Error(`OpenRouter API error ${response.status}: ${txt}`);
    }
    const result: any = await response.json();
    const content = result?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || !content.trim()) throw new Error("OpenRouter returned an empty or unexpected response.");
    return content;
  } catch (err) {
    if ((err as Error).name === "AbortError") throw new Error("OpenRouter request timed out after 120 seconds.");
    throw err;
  } finally { clearTimeout(timeout); }
}

/**
 * Call an agent and parse the response as JSON, with up to `maxRetries`
 * automatic retries when the model returns malformed JSON.
 *
 * On each retry the model is told what JSON parsing error occurred and asked
 * to fix it. If all retries are exhausted the function returns `null` —
 * the caller should treat that as a `parse_failed` signal.
 */
export async function callJsonAgent<T>(
  systemPrompt: string,
  userContent: string,
  model: string,
  apiKey: string,
  maxRetries: number = 2
): Promise<T | null> {
  let lastError = "";
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const content =
      attempt === 0
        ? userContent
        : `Your previous response was invalid JSON (${lastError}). Return only a corrected JSON object matching the requested schema. Do not repeat or modify the input data.\n\nInput follows:\n${userContent}`;

    const raw = await callAgent(systemPrompt, content, model, apiKey);
    try {
      const trimmed = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
      const first = trimmed.indexOf("{");
      const last = trimmed.lastIndexOf("}");
      if (first < 0 || last < first) throw new Error("No JSON object found in model response");
      return JSON.parse(trimmed.slice(first, last + 1)) as T;
    } catch (e) {
      lastError = (e as Error).message;
      if (attempt === maxRetries) {
        return null; // caller should interpret this as parse_failed
      }
    }
  }
  return null;
}
