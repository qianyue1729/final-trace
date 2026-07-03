export interface StandaloneConfig {
  deploymentUrl: string;
  assistantId: string;
  langsmithApiKey?: string;
}

const CONFIG_KEY = "deep-agent-config";

export function getDefaultConfig(): StandaloneConfig | null {
  const deploymentUrl =
    process.env.NEXT_PUBLIC_DEPLOYMENT_URL || "http://127.0.0.1:2024";
  const assistantId = process.env.NEXT_PUBLIC_ASSISTANT_ID || "trace_agent";

  return {
    deploymentUrl,
    assistantId,
    langsmithApiKey: process.env.NEXT_PUBLIC_LANGSMITH_API_KEY || undefined,
  };
}

export function getConfig(): StandaloneConfig | null {
  if (typeof window === "undefined") return null;

  const stored = localStorage.getItem(CONFIG_KEY);
  if (!stored) return getDefaultConfig();

  try {
    return JSON.parse(stored);
  } catch {
    return null;
  }
}

export function saveConfig(config: StandaloneConfig): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
}
