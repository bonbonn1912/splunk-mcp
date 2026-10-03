import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { SplunkMcpError } from "./errors.js";

const VERSION = "v1";

export function generateSecret(): string {
  return randomBytes(32).toString("base64");
}

function keyFromSecret(secret: string): Buffer {
  const key = Buffer.from(secret.trim(), "base64");
  if (key.length !== 32) {
    throw new SplunkMcpError("DECRYPT_FAILED", "SPLUNK_SECRET must be 32 random bytes encoded as Base64.", {
      hint: "Run `node dist/cli.js encrypt --write` to create a matching secret and encrypted password in .env.",
    });
  }
  return key;
}

/** AES-256-GCM. Output: v1:<iv>:<authTag>:<ciphertext>, all parts Base64. */
export function encryptPassword(password: string, secret: string): string {
  const key = keyFromSecret(secret);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(password, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv.toString("base64"), tag.toString("base64"), ciphertext.toString("base64")].join(":");
}

export function decryptPassword(encrypted: string, secret: string): string {
  const key = keyFromSecret(secret);
  const parts = encrypted.trim().split(":");
  const fail = () =>
    new SplunkMcpError("DECRYPT_FAILED", "SPLUNK_PASSWORD_ENC could not be decrypted with SPLUNK_SECRET.", {
      hint: "Run `node dist/cli.js encrypt --write` again; it replaces both values in .env.",
    });
  if (parts.length !== 4 || parts[0] !== VERSION) throw fail();
  try {
    const iv = Buffer.from(parts[1]!, "base64");
    const tag = Buffer.from(parts[2]!, "base64");
    const ciphertext = Buffer.from(parts[3]!, "base64");
    if (iv.length !== 12 || tag.length !== 16) throw fail();
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    throw fail();
  }
}
