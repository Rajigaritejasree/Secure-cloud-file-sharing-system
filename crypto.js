const crypto = require("crypto");

const algorithm = "aes-256-gcm";

function getEncryptionKey() {
  const secret = process.env.FILE_ENCRYPTION_SECRET;

  if (!secret) {
    throw new Error("FILE_ENCRYPTION_SECRET is missing. Add it to your environment variables.");
  }

  return crypto.scryptSync(secret, "secure-file-sharing-salt", 32);
}

function encryptBuffer(buffer) {
  const iv = crypto.randomBytes(16);
  const key = getEncryptionKey();
  const cipher = crypto.createCipheriv(algorithm, key, iv);

  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encrypted,
    encryption: {
      iv: iv.toString("hex"),
      authTag: authTag.toString("hex"),
      algorithm,
    },
  };
}

function decryptBuffer(buffer, encryption) {
  const key = getEncryptionKey();
  const decipher = crypto.createDecipheriv(
    encryption.algorithm || algorithm,
    key,
    Buffer.from(encryption.iv, "hex")
  );

  decipher.setAuthTag(Buffer.from(encryption.authTag, "hex"));

  return Buffer.concat([decipher.update(buffer), decipher.final()]);
}

module.exports = {
  encryptBuffer,
  decryptBuffer,
};
