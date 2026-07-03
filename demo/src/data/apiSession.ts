/**
 * API client — fetches real traced LOCK sessions from soar_mcp_env via Python backend.
 */
import type { DemoSession, ScenarioInfo } from '../types';
import { mockSession } from './mockSession';

const HEALTH_URL = '/api/health';
const SCENARIOS_URL = '/api/scenarios';

/** Check if the Python backend is running. */
export async function checkBackend(): Promise<boolean> {
  try {
    const resp = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(2000) });
    return resp.ok;
  } catch {
    return false;
  }
}

/** List soar_mcp_env scenarios. */
export async function fetchScenarios(): Promise<ScenarioInfo[]> {
  try {
    const resp = await fetch(SCENARIOS_URL, { signal: AbortSignal.timeout(5000) });
    if (!resp.ok) return [];
    const data = await resp.json();
    return Array.isArray(data) ? (data as ScenarioInfo[]) : [];
  } catch (err) {
    console.warn('[apiSession] Failed to load scenarios:', err);
    return [];
  }
}

/** Fetch traced session for a scenario. Returns null on failure. */
export async function fetchSession(scenarioId: string): Promise<DemoSession | null> {
  const url = `/api/session?scenario=${encodeURIComponent(scenarioId)}`;
  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(180000) });
    if (!resp.ok) {
      const err = await resp.text();
      console.warn('[apiSession] Backend error:', err);
      return null;
    }
    const data = await resp.json();
    if (!data || !data.rounds || !Array.isArray(data.rounds)) return null;
    return data as DemoSession;
  } catch (err) {
    console.warn('[apiSession] Backend unavailable:', err);
    return null;
  }
}

/** Fallback mock when backend is down (dev only). */
export function getMockSession(): DemoSession {
  return mockSession;
}
