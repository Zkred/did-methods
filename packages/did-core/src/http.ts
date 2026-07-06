import { DidError, ResolutionErrorCode } from "./errors.js";

export interface FetchJsonOptions {
  /** Abort the request after this many milliseconds. Default: 15000. */
  timeoutMs?: number;
  /** Custom fetch implementation (for testing or non-standard environments). */
  fetchImpl?: typeof fetch;
  /** Extra request headers. */
  headers?: Record<string, string>;
}

/**
 * GET a URL and parse the response as JSON, mapping HTTP failures onto
 * standard DID resolution error codes.
 */
export async function fetchJson<T = unknown>(url: string, options: FetchJsonOptions = {}): Promise<T> {
  const { timeoutMs = 15_000, fetchImpl = fetch, headers = {} } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetchImpl(url, {
      headers: { accept: "application/json", ...headers },
      redirect: "follow",
      signal: controller.signal,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new DidError(ResolutionErrorCode.InternalError, `request to ${url} failed: ${message}`);
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 404) {
    throw new DidError(ResolutionErrorCode.NotFound, `document not found at ${url}`);
  }
  if (!response.ok) {
    throw new DidError(
      ResolutionErrorCode.InternalError,
      `unexpected HTTP ${response.status} from ${url}`,
    );
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new DidError(
      ResolutionErrorCode.RepresentationNotSupported,
      `response from ${url} is not valid JSON`,
    );
  }
}