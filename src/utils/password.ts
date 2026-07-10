const ITERATIONS = 100_000;
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await deriveKey(password, salt);
  const hash = await crypto.subtle.exportKey("raw", key);

  const saltBase64 = bufferToBase64(salt);
  const hashBase64 = bufferToBase64(new Uint8Array(hash));

  return `${ITERATIONS}:${saltBase64}:${hashBase64}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [iterStr, saltBase64, hashBase64] = stored.split(":");
  const iterations = parseInt(iterStr, 10);
  const salt = base64ToBuffer(saltBase64);
  const expectedHash = base64ToBuffer(hashBase64);

  const key = await deriveKey(password, salt, iterations);
  const actualHash = new Uint8Array(await crypto.subtle.exportKey("raw", key));

  if (actualHash.length !== expectedHash.length) {
    return false;
  }

  let mismatch = 0;
  for (let i = 0; i < actualHash.length; i++) {
    mismatch |= actualHash[i] ^ expectedHash[i];
  }
  return mismatch === 0;
}

async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations = ITERATIONS,
): Promise<CryptoKey> {
  const encoded = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey("raw", encoded, "PBKDF2", false, ["deriveBits", "deriveKey"]);

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "HMAC", hash: "SHA-256", length: KEY_LENGTH * 8 },
    true,
    ["sign"],
  );
}

function bufferToBase64(buffer: Uint8Array): string {
  let binary = "";
  for (const byte of buffer) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
