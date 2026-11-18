import 'dotenv/config'; // load .env before any module reads process.env
import express from 'express';
import cors from 'cors';
import { ensureDb } from './utils/db.js';
import trainRoutes from './routes/trainRoutes.js';
import stationRoutes from './routes/stationRoutes.js';
import authRoutes from './routes/authRoutes.js';
import { initData } from './utils/dataLoader.js';


const app = express();
const PORT = process.env.PORT || 5000;

// Behind Vercel's proxy: use the real client IP (needed for rate limiting)
app.set('trust proxy', 1);

// Initialize data loader for Kaggle dataset
initData();

app.use(cors());
app.use(express.json());

app.use('/api/trains', trainRoutes);
app.use('/api/stations', stationRoutes);
app.use('/api/auth', authRoutes);

// Database connection (same helper the auth routes use, so they share one attempt)
ensureDb().then((ok) => {
  if (ok) console.log('Connected to MongoDB');
  else console.error('⚠️ Failed to connect to MongoDB. Running in memory fallback mode.');
});

// Global error handler to catch unhandled promise rejections in Express 5
app.use((err, req, res, next) => {
  console.error('Unhandled Global Error:', err);
  res.status(500).json({ success: false, message: err.message || 'Internal Server Error' });
});

// Only listen on port if running locally (not on Vercel)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

// Export the app for Vercel Serverless
export default app;
