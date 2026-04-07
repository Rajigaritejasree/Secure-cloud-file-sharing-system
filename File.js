const mongoose = require("mongoose");

const sharedUserSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    permission: {
      type: String,
      enum: ["view"],
      default: "view",
    },
    sharedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false }
);

const shareLinkSchema = new mongoose.Schema(
  {
    token: {
      type: String,
      required: true,
      unique: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    revokedAt: Date,
  },
  { _id: false }
);

const fileSchema = new mongoose.Schema(
  {
    originalName: {
      type: String,
      required: true,
      trim: true,
    },
    storedName: {
      type: String,
      required: true,
      unique: true,
    },
    mimeType: {
      type: String,
      required: true,
    },
    size: {
      type: Number,
      required: true,
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    sharedWith: [sharedUserSchema],
    shareLinks: [shareLinkSchema],
    encryption: {
      iv: { type: String, required: true },
      authTag: { type: String, required: true },
      algorithm: { type: String, required: true, default: "aes-256-gcm" },
    },
    accessLogs: [
      {
        actor: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        action: {
          type: String,
          enum: ["upload", "download", "share-user", "share-link", "revoke-link", "delete"],
          required: true,
        },
        ip: String,
        userAgent: String,
        timestamp: {
          type: Date,
          default: Date.now,
        },
      },
    ],
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("File", fileSchema);
