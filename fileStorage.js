const fs = require("fs/promises");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const uploadsDir = path.join(__dirname, "..", "uploads");

function buildStoredName(originalName) {
  const extension = path.extname(originalName);
  return `${uuidv4()}${extension}.enc`;
}

function getStoredFilePath(storedName) {
  return path.join(uploadsDir, storedName);
}

async function writeEncryptedFile(storedName, buffer) {
  await fs.writeFile(getStoredFilePath(storedName), buffer);
}

async function readEncryptedFile(storedName) {
  return fs.readFile(getStoredFilePath(storedName));
}

async function removeEncryptedFile(storedName) {
  try {
    await fs.unlink(getStoredFilePath(storedName));
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
}

module.exports = {
  buildStoredName,
  writeEncryptedFile,
  readEncryptedFile,
  removeEncryptedFile,
};
