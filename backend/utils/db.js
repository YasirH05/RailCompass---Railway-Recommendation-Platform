import mongoose from 'mongoose';

// Long enough for a cold connection to Atlas, short enough to answer well
// inside the serverless function time limit.
const CONNECT_TIMEOUT_MS = 7000;

const getUri = () => (process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/railwise').replace(/\s+/g, '');

export const isDbReady = () => mongoose.connection.readyState === 1;

// Wait for a connection attempt that is already in progress. Calling
// mongoose.connect() again while connecting returns immediately without
// waiting, so we listen for the outcome instead.
const waitForConnection = (ms) => new Promise((resolve) => {
  const conn = mongoose.connection;
  const finish = () => {
    clearTimeout(timer);
    conn.off('connected', finish);
    conn.off('error', finish);
    conn.off('disconnected', finish);
    resolve(isDbReady());
  };
  const timer = setTimeout(finish, ms);
  conn.on('connected', finish);
  conn.on('error', finish);
  conn.on('disconnected', finish);
});

// Connect (or reconnect) and report whether the DB is usable.
export const ensureDb = async () => {
  if (isDbReady()) return true;

  if (mongoose.connection.readyState === 2) {
    if (await waitForConnection(CONNECT_TIMEOUT_MS)) return true;
    if (mongoose.connection.readyState === 2) return false; // still stuck connecting
  }

  try {
    await mongoose.connect(getUri(), {
      serverSelectionTimeoutMS: CONNECT_TIMEOUT_MS,
      connectTimeoutMS: CONNECT_TIMEOUT_MS,
    });
  } catch (err) {
    console.error('MongoDB connect failed:', err.message);
  }
  return isDbReady();
};
