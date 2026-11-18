import mongoose from 'mongoose';

const getUri = () => (process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/railwise').replace(/\s+/g, '');

export const isDbReady = () => mongoose.connection.readyState === 1;

// Connect (or reconnect) with short timeouts so a request never hangs past
// Vercel's ~10s function limit. Returns true when the DB is usable.
export const ensureDb = async () => {
  if (isDbReady()) return true;
  try {
    await mongoose.connect(getUri(), {
      serverSelectionTimeoutMS: 4000,
      connectTimeoutMS: 4000,
    });
  } catch (err) {
    console.error('MongoDB connect failed:', err.message);
  }
  return isDbReady();
};
