const mongoose = require("mongoose");

async function connectDb() {
  const mongoUri = process.env.MONGODB_URI;

  if (!mongoUri) {
    throw new Error("MONGODB_URI is missing.");
  }

  await mongoose.connect(mongoUri, {
    dbName: process.env.MONGODB_DB || "secure-file-sharing",
  });

  console.log("MongoDB connected");
}

module.exports = connectDb;
