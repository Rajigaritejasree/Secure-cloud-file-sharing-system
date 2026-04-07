const mongoose = require("mongoose");

let isConnected = false;

async function connectDb() {
  if (isConnected) {
    return mongoose.connection;
  }

  const mongoUri = process.env.MONGODB_URI;

  if (!mongoUri) {
    throw new Error("MONGODB_URI is missing. Add it to your environment variables.");
  }

  mongoose.set("strictQuery", true);

  await mongoose.connect(mongoUri, {
    dbName: process.env.MONGODB_DB || undefined,
  });

  isConnected = true;
  console.log("MongoDB connected");
  return mongoose.connection;
}

module.exports = connectDb;
