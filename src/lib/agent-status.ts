export const AgentStatus = {
  Starting: "Starting",
  Onboarding: "Onboarding",
  AwaitingRedirect: "Awaiting Redirect Url",
  AwaitingGateway: "Awaiting Gateway",
  AgentWarmup: "Agent Warmup",
  PreparingTradingAccount: "Preparing Trading Account",
  StrategyBuilding: "Strategy Building",
  TradingWalletGenerating: "Trading Wallet Generating",
  AwaitingDeposit: "Awaiting Deposit",
  LiveTrading: "Live Trading",
  Stopped: "Stopped",
  Cancelled: "Cancelled",
} as const;

export type AgentStatusValue = (typeof AgentStatus)[keyof typeof AgentStatus];

const legacyMap: Record<string, AgentStatusValue> = {
  starting: AgentStatus.Starting,
  awaiting_auth: AgentStatus.AwaitingRedirect,
  verifying: AgentStatus.Onboarding,
  ready: AgentStatus.StrategyBuilding,
  failed: AgentStatus.Cancelled,
  "trading wallet generating": AgentStatus.PreparingTradingAccount,
};

export function normalizeAgentStatus(status?: string | null): AgentStatusValue {
  if (!status) return AgentStatus.Starting;
  if (Object.values(AgentStatus).includes(status as AgentStatusValue)) {
    return status as AgentStatusValue;
  }
  const normalized = status.toLowerCase();
  return legacyMap[normalized] ?? AgentStatus.Starting;
}

export const ActiveAgentStatuses: AgentStatusValue[] = [
  AgentStatus.Starting,
  AgentStatus.Onboarding,
  AgentStatus.AwaitingRedirect,
  AgentStatus.AwaitingGateway,
  AgentStatus.AgentWarmup,
  AgentStatus.PreparingTradingAccount,
  AgentStatus.StrategyBuilding,
  AgentStatus.TradingWalletGenerating,
  AgentStatus.AwaitingDeposit,
  AgentStatus.LiveTrading,
];
