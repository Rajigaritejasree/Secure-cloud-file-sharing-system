const express = require("express");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");

const File = require("../models/File");
const User = require("../models/User");
const { requireAuth } = require("../middleware/auth");
const { encryptBuffer, decryptBuffer } = require("../utils/crypto");
const {
  buildStoredName,
  writeEncryptedFile,
  readEncryptedFile,
  removeEncryptedFile,
} = require("../utils/fileStorage");

const router = express.Router();

const allowedMimeTypes = new Set([
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/gif",
  "text/plain",
  "application/zip",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/msword",
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: Number(process.env.MAX_FILE_SIZE_BYTES || 5 * 1024 * 1024),
    files: 1,
  },
  fileFilter: (_req, file, cb) => {
    if (!allowedMimeTypes.has(file.mimetype)) {
      return cb(new Error("Unsupported file type."));
    }

    return cb(null, true);
  },
});

function getRequestMeta(req) {
  return {
    ip: req.ip,
    userAgent: req.get("user-agent") || "unknown",
  };
}

function serializeFile(file, currentUserId) {
  const currentId = currentUserId?.toString();
  const isOwner = file.owner?._id
    ? file.owner._id.toString() === currentId
    : file.owner.toString() === currentId;

  return {
    id: file._id,
    originalName: file.originalName,
    mimeType: file.mimeType,
    size: file.size,
    owner: file.owner.username
      ? {
          id: file.owner._id,
          username: file.owner.username,
        }
      : file.owner,
    createdAt: file.createdAt,
    updatedAt: file.updatedAt,
    isOwner,
    sharedWith: file.sharedWith.map((entry) => ({
      userId: entry.user?._id || entry.user,
      username: entry.user?.username,
      permission: entry.permission,
      sharedAt: entry.sharedAt,
    })),
    shareLinks: isOwner
      ? file.shareLinks.map((link) => ({
          token: link.token,
          expiresAt: link.expiresAt,
          revokedAt: link.revokedAt || null,
          isActive: !link.revokedAt && new Date(link.expiresAt) > new Date(),
        }))
      : [],
  };
}

async function canAccessFile(file, userId) {
  const ownerId = file.owner._id ? file.owner._id.toString() : file.owner.toString();
  if (ownerId === userId.toString()) {
    return true;
  }

  return file.sharedWith.some((entry) => {
    const sharedId = entry.user._id ? entry.user._id.toString() : entry.user.toString();
    return sharedId === userId.toString();
  });
}

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const files = await File.find({
      $or: [{ owner: req.user._id }, { "sharedWith.user": req.user._id }],
    })
      .populate("owner", "username")
      .populate("sharedWith.user", "username")
      .sort({ createdAt: -1 });

    res.json({
      files: files.map((file) => serializeFile(file, req.user._id)),
    });
  } catch (error) {
    next(error);
  }
});

router.post("/", requireAuth, upload.single("file"), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "A file is required." });
    }

    const duplicate = await File.findOne({
      owner: req.user._id,
      originalName: req.file.originalname,
      size: req.file.size,
    });

    if (duplicate) {
      return res.status(409).json({ message: "This file already exists in your vault." });
    }

    const { encrypted, encryption } = encryptBuffer(req.file.buffer);
    const storedName = buildStoredName(req.file.originalname);

    await writeEncryptedFile(storedName, encrypted);

    const file = await File.create({
      originalName: req.file.originalname,
      storedName,
      mimeType: req.file.mimetype,
      size: req.file.size,
      owner: req.user._id,
      encryption,
      accessLogs: [
        {
          actor: req.user._id,
          action: "upload",
          ...getRequestMeta(req),
        },
      ],
    });

    const hydratedFile = await File.findById(file._id)
      .populate("owner", "username")
      .populate("sharedWith.user", "username");

    return res.status(201).json({
      message: "File uploaded and encrypted successfully.",
      file: serializeFile(hydratedFile, req.user._id),
    });
  } catch (error) {
    return next(error);
  }
});

router.post("/:fileId/share/user", requireAuth, async (req, res, next) => {
  try {
    const { fileId } = req.params;
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ message: "Target username is required." });
    }

    const file = await File.findById(fileId);

    if (!file) {
      return res.status(404).json({ message: "File not found." });
    }

    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Only the owner can share this file." });
    }

    const targetUser = await User.findOne({ username: username.trim() }).select("_id username");

    if (!targetUser) {
      return res.status(404).json({ message: "Target user not found." });
    }

    if (targetUser._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: "You already own this file." });
    }

    const alreadyShared = file.sharedWith.some(
      (entry) => entry.user.toString() === targetUser._id.toString()
    );

    if (alreadyShared) {
      return res.status(409).json({ message: "File is already shared with this user." });
    }

    file.sharedWith.push({
      user: targetUser._id,
      permission: "view",
      sharedAt: new Date(),
    });
    file.accessLogs.push({
      actor: req.user._id,
      action: "share-user",
      ...getRequestMeta(req),
    });

    await file.save();

    return res.json({
      message: `File shared with ${targetUser.username}.`,
    });
  } catch (error) {
    return next(error);
  }
});

router.post("/:fileId/share/link", requireAuth, async (req, res, next) => {
  try {
    const { fileId } = req.params;
    const { expiresInHours = 24 } = req.body;

    const file = await File.findById(fileId);

    if (!file) {
      return res.status(404).json({ message: "File not found." });
    }

    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Only the owner can create a share link." });
    }

    const safeHours = Math.min(Math.max(Number(expiresInHours), 1), 168);
    const expiresAt = new Date(Date.now() + safeHours * 60 * 60 * 1000);
    const token = uuidv4();

    file.shareLinks.push({
      token,
      expiresAt,
      createdBy: req.user._id,
    });
    file.accessLogs.push({
      actor: req.user._id,
      action: "share-link",
      ...getRequestMeta(req),
    });

    await file.save();

    return res.status(201).json({
      message: "Share link created successfully.",
      shareLink: {
        token,
        expiresAt,
        url: `/api/files/public/${token}/download`,
      },
    });
  } catch (error) {
    return next(error);
  }
});

router.get("/public/:token/download", async (req, res, next) => {
  try {
    const { token } = req.params;

    const file = await File.findOne({ "shareLinks.token": token });

    if (!file) {
      return res.status(404).json({ message: "Share link not found." });
    }

    const shareLink = file.shareLinks.find((link) => link.token === token);

    if (!shareLink || shareLink.revokedAt) {
      return res.status(403).json({ message: "Share link is no longer valid." });
    }

    if (new Date(shareLink.expiresAt) <= new Date()) {
      return res.status(403).json({ message: "Share link has expired." });
    }

    const encryptedFile = await readEncryptedFile(file.storedName);
    const decryptedFile = decryptBuffer(encryptedFile, file.encryption);

    file.accessLogs.push({
      action: "download",
      ...getRequestMeta(req),
    });
    await file.save();

    res.setHeader("Content-Type", file.mimeType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${encodeURIComponent(file.originalName)}"`
    );
    return res.send(decryptedFile);
  } catch (error) {
    return next(error);
  }
});

router.get("/:fileId/download", requireAuth, async (req, res, next) => {
  try {
    const file = await File.findById(req.params.fileId)
      .populate("owner", "username")
      .populate("sharedWith.user", "username");

    if (!file) {
      return res.status(404).json({ message: "File not found." });
    }

    const hasAccess = await canAccessFile(file, req.user._id);

    if (!hasAccess) {
      return res.status(403).json({ message: "You do not have access to this file." });
    }

    const encryptedFile = await readEncryptedFile(file.storedName);
    const decryptedFile = decryptBuffer(encryptedFile, file.encryption);

    file.accessLogs.push({
      actor: req.user._id,
      action: "download",
      ...getRequestMeta(req),
    });
    await file.save();

    res.setHeader("Content-Type", file.mimeType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${encodeURIComponent(file.originalName)}"`
    );

    return res.send(decryptedFile);
  } catch (error) {
    return next(error);
  }
});

router.delete("/:fileId", requireAuth, async (req, res, next) => {
  try {
    const file = await File.findById(req.params.fileId);

    if (!file) {
      return res.status(404).json({ message: "File not found." });
    }

    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Only the owner can delete this file." });
    }

    file.accessLogs.push({
      actor: req.user._id,
      action: "delete",
      ...getRequestMeta(req),
    });

    await removeEncryptedFile(file.storedName);
    await File.deleteOne({ _id: file._id });

    return res.json({ message: "File deleted successfully." });
  } catch (error) {
    return next(error);
  }
});

router.patch("/:fileId/share-link/:token/revoke", requireAuth, async (req, res, next) => {
  try {
    const { fileId, token } = req.params;
    const file = await File.findById(fileId);

    if (!file) {
      return res.status(404).json({ message: "File not found." });
    }

    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Only the owner can revoke share links." });
    }

    const shareLink = file.shareLinks.find((entry) => entry.token === token);

    if (!shareLink) {
      return res.status(404).json({ message: "Share link not found." });
    }

    shareLink.revokedAt = new Date();
    file.accessLogs.push({
      actor: req.user._id,
      action: "revoke-link",
      ...getRequestMeta(req),
    });

    await file.save();

    return res.json({ message: "Share link revoked successfully." });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
