import bs58 from "bs58";
import { verifyAsync as ed25519VerifyAsync } from "@noble/ed25519";

const DEFAULT_MAX_AGE_MS = 5 * 60 * 1000;

function base64ToBytes(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function decodeSignature(signature: string) {
  try {
    return bs58.decode(signature);
  } catch {
    return base64ToBytes(signature);
  }
}

export function buildAuthMessage({
  domain,
  walletAddress,
  timestamp,
}: {
  domain: string;
  walletAddress: string;
  timestamp: string;
}) {
  return [
    `${domain} wants you to sign in with your Solana account:`,
    walletAddress,
    "",
    "Sign this message to authenticate with Deserve Trade.",
    "",
    `Issued At: ${timestamp}`,
  ].join("\n");
}

export function isTimestampFresh(timestamp: string, maxAgeMs = DEFAULT_MAX_AGE_MS) {
  const timestampMs = Date.parse(timestamp);
  if (Number.isNaN(timestampMs)) return false;
  const skew = Math.abs(Date.now() - timestampMs);
  return skew <= maxAgeMs;
}

export async function verifySignature({
  message,
  signature,
  walletAddress,
}: {
  message: string;
  signature: string;
  walletAddress: string;
}) {
  const messageBytes = new TextEncoder().encode(message);
  const signatureBytes = decodeSignature(signature);
  const publicKeyBytes = bs58.decode(walletAddress);
  return ed25519VerifyAsync(signatureBytes, messageBytes, publicKeyBytes);
}
