import express from 'express';
import rateLimit from 'express-rate-limit';
import { googleLogin, updatePreferences, getMe, protect, register, login, updateProfile, forgotPassword, resetPassword } from '../controllers/authController.js';

const router = express.Router();

// Per-IP rate limits. On Vercel each serverless instance keeps its own counter,
// so these slow down scripted abuse rather than guarantee an exact cap.
const limiter = (windowMinutes, limit, message) => rateLimit({
  windowMs: windowMinutes * 60 * 1000,
  limit,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, message },
});

const signupLimiter = limiter(60, 5, 'Too many accounts created from this network. Please try again later.');
const loginLimiter = limiter(15, 20, 'Too many sign-in attempts. Please wait a few minutes and try again.');
const resetLimiter = limiter(60, 5, 'Too many password reset requests. Please try again later.');

// Public routes
router.post('/google', loginLimiter, googleLogin);
router.post('/register', signupLimiter, register);
router.post('/login', loginLimiter, login);
router.post('/forgot-password', resetLimiter, forgotPassword);
router.post('/reset-password/:token', loginLimiter, resetPassword);

// Protected routes (require valid JWT)
router.get('/me', protect, getMe);
router.post('/onboarding', protect, updatePreferences);
router.put('/profile', protect, updateProfile);

export default router;
