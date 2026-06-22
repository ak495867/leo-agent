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
  systemPrompt: string,
  userContent: string,
  model: string,
  apiKey: string
): Promise<string> {
  const combined = systemPrompt + "\n" + userContent;
  const estimatedTokens = estimateTokenCount(combined);
  if (estimatedTokens > 80_000) {
    // Truncate user content until we're under the limit
    const maxChars = 80_000 * CHARS_PER_TOKEN - systemPrompt.length - 500; // 500 safety margin
    if (maxChars > 0 && userContent.length > maxChars) {
      userContent =
        userContent.slice(0, Math.floor(maxChars)) +
        `\n\n[... truncated — original input was ~${estimatedTokens}K tokens]`;
    } else {
      throw new Error(
        `Estimated token count (${estimatedTokens}) exceeds 80 K limit even after truncation. ` +
        `System prompt alone may be too large.`
      );
    }
  }

  const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "https://github.com/leo-agent/cli",
      "X-Title": "Leo Security Agent"
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userContent }
      ]
    })
  });

  if (!response.ok) {
    const txt = await response.text();
    throw new Error(`OpenRouter API error ${response.status}: ${txt}`);
  }

  const result: any = await response.json();
  if (!result?.choices?.[0]?.message?.content) {
    const preview = JSON.stringify(result).slice(0, 300);
    throw new Error(
      `OpenRouter returned an unexpected response structure. ` +
      `Expected choices[0].message.content. Got: ${preview}`
    );
  }
  return result.choices[0].message.content as string;
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
        : `You previously returned invalid JSON. The parse error was:\n${lastError}\n\nPlease fix your output and return ONLY valid JSON matching the required schema. No commentary.\n\nOriginal input:\n${userContent}`;

    const raw = await callAgent(systemPrompt, content, model, apiKey);
    try {
      return JSON.parse(raw) as T;
    } catch (e) {
      lastError = (e as Error).message;
      if (attempt === maxRetries) {
        return null; // caller should interpret this as parse_failed
      }
    }
  }
  return null;
}
