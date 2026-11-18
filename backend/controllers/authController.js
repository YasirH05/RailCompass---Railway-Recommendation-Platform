import { OAuth2Client } from 'google-auth-library';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import crypto from 'crypto';
import User from '../models/User.js';
import { sendEmail } from '../utils/sendEmail.js';
import { ensureDb, isDbReady } from '../utils/db.js';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '765017417232-fp5ui38tgrjkvsnvv9mpl8ga9pneliq3.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Secret for our own JWT tokens. The fallback is public (it is in the repo), so
// production must set JWT_SECRET in its environment.
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-railcompass-key-123';
if (!process.env.JWT_SECRET) {
  console.warn('⚠️ JWT_SECRET is not set. Using an insecure fallback secret; set JWT_SECRET in the environment.');
}

const MIN_PASSWORD_LENGTH = 6;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const normalizeEmail = (email) => String(email || '').trim().toLowerCase();

// Base URL used in emails (reset links, logo). Never derived from request
// headers, which an attacker could spoof to steal reset tokens.
const appUrl = () =>
  (process.env.APP_URL || (process.env.NODE_ENV === 'production' ? 'https://railcompass.dev' : 'http://localhost:5173')).replace(/\/+$/, '');

const signToken = (user, includeUserData = false) =>
  jwt.sign(
    {
      userId: user._id,
      isOnboarded: user.isOnboarded,
      userData: includeUserData ? user : undefined,
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

const toSafeUser = (user) => {
  const obj = typeof user.toObject === 'function' ? user.toObject() : { ...user };
  delete obj.password;
  delete obj.resetPasswordToken;
  delete obj.resetPasswordExpires;
  return obj;
};

const dbUnavailable = (res) =>
  res.status(503).json({ success: false, message: 'Our account service is temporarily unavailable. Please try again in a minute.' });

export const googleLogin = async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ success: false, message: 'Missing Google credential' });
    }

    const ticket = await client.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { sub: googleId, name, picture } = payload;
    const email = normalizeEmail(payload.email);

    if (!payload.email_verified) {
      return res.status(401).json({ success: false, message: 'Your Google email address is not verified.' });
    }

    let user = null;
    await ensureDb();

    if (!isDbReady()) {
      // In-memory fallback so Google sign-in still works during a DB outage
      global.memoryUsers = global.memoryUsers || [];
      user = global.memoryUsers.find(u => u.googleId === googleId);

      if (!user) {
        user = {
          _id: new mongoose.Types.ObjectId().toString(),
          googleId, email, name, picture, isOnboarded: false,
          preferences: {
            weightDuration: 0.35, weightDaytime: 0.25, weightBudget: 0.20,
            weightReliability: 0.10, weightComfort: 0.05, weightFood: 0.05,
            preferredClass: 'All'
          }
        };
        global.memoryUsers.push(user);
      }
    } else {
      // One account per email: link Google to an existing email/password account
      user = await User.findOne({ email });

      if (user) {
        if (!user.googleId) {
          user.googleId = googleId;
          if (!user.picture && picture) user.picture = picture;
          await user.save();
        }
      } else {
        user = new User({ googleId, email, name, picture });
        await user.save();
      }
    }

    const dbDown = !isDbReady();
    const token = signToken(user, dbDown);

    res.status(200).json({ success: true, token, user: dbDown ? user : toSafeUser(user) });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(401).json({ success: false, message: 'Google sign-in failed. Please try again.' });
  }
};

// Protect routes middleware
export const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authorized to access this route' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    await ensureDb();

    if (!isDbReady()) {
      if (decoded.userData) {
        req.user = decoded.userData;
      } else {
        global.memoryUsers = global.memoryUsers || [];
        req.user = global.memoryUsers.find(u => u._id === decoded.userId || u._id === decoded.userId.toString());
      }
    } else {
      req.user = await User.findById(decoded.userId).select('-password -resetPasswordToken -resetPasswordExpires');
    }

    if (!req.user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Not authorized to access this route' });
  }
};

export const updatePreferences = async (req, res) => {
  try {
    const { preferences } = req.body;

    let user;
    let newToken = null;

    if (!isDbReady()) {
      user = req.user;
      user.preferences = { ...user.preferences, ...preferences };
      user.isOnboarded = true;

      global.memoryUsers = global.memoryUsers || [];
      const idx = global.memoryUsers.findIndex(u => u._id === user._id);
      if (idx !== -1) {
        global.memoryUsers[idx] = user;
      } else {
        global.memoryUsers.push(user);
      }

      newToken = signToken(user, true);
    } else {
      user = await User.findByIdAndUpdate(
        req.user._id,
        { preferences, isOnboarded: true },
        { new: true, runValidators: true }
      );
      user = toSafeUser(user);
    }

    res.status(200).json({ success: true, user, token: newToken });
  } catch (error) {
    console.error('Error updating preferences:', error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};

export const getMe = async (req, res) => {
  res.status(200).json({ success: true, user: req.user });
};

export const register = async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!name || name.length > 80) {
      return res.status(400).json({ success: false, message: 'Please enter your name (up to 80 characters).' });
    }
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ success: false, message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
    }

    if (!(await ensureDb())) return dbUnavailable(res);

    const existing = await User.findOne({ email });
    if (existing) {
      const message = existing.password
        ? 'An account with this email already exists. Please sign in instead.'
        : 'This email is already registered with Google. Use "Continue with Google", or use "Forgot password" to add a password to that account.';
      return res.status(400).json({ success: false, message });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, isOnboarded: false });
    await user.save();

    res.status(201).json({ success: true, token: signToken(user), user: toSafeUser(user) });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ success: false, message: 'An account with this email already exists. Please sign in instead.' });
    }
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};

export const login = async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Please enter your email and password.' });
    }

    if (!(await ensureDb())) return dbUnavailable(res);

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }
    if (!user.password) {
      return res.status(400).json({
        success: false,
        message: 'This account was created with Google. Use "Continue with Google", or use "Forgot password" to set a password.'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    res.status(200).json({ success: true, token: signToken(user), user: toSafeUser(user) });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const { name, age, phone, favouriteJourney, preferences } = req.body;
    let user;
    let newToken = null;

    if (!isDbReady()) {
      user = req.user;
      if (name !== undefined) user.name = name;
      if (age !== undefined) user.age = age;
      if (phone !== undefined) user.phone = phone;
      if (favouriteJourney !== undefined) user.favouriteJourney = favouriteJourney;
      if (preferences !== undefined) user.preferences = { ...user.preferences, ...preferences };

      global.memoryUsers = global.memoryUsers || [];
      const idx = global.memoryUsers.findIndex(u => u._id === user._id);
      if (idx !== -1) {
        global.memoryUsers[idx] = user;
      } else {
        global.memoryUsers.push(user);
      }

      newToken = signToken(user, true);
    } else {
      const updateData = {};
      if (name !== undefined) updateData.name = name;
      if (age !== undefined) updateData.age = age;
      if (phone !== undefined) updateData.phone = phone;
      if (favouriteJourney !== undefined) updateData.favouriteJourney = favouriteJourney;
      if (preferences !== undefined) updateData.preferences = preferences;

      user = await User.findByIdAndUpdate(req.user._id, updateData, { new: true, runValidators: true });
      user = toSafeUser(user);
    }

    res.status(200).json({ success: true, user, token: newToken });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};

export const forgotPassword = async (req, res) => {
  const genericReply = { success: true, message: 'If an account exists for that email, a reset link has been sent.' };
  try {
    const email = normalizeEmail(req.body.email);
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
    }

    if (!(await ensureDb())) return dbUnavailable(res);

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(200).json(genericReply);
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const baseUrl = appUrl();
    const resetUrl = `${baseUrl}/reset-password/${resetToken}`;
    const message = `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 40px 20px; text-align: center;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #1e293b; padding: 40px; border-radius: 12px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">

          <div style="margin-bottom: 30px;">
            <img src="${baseUrl}/logo.png" alt="Rail Compass Logo" style="width: 80px; height: auto;" />
            <h1 style="color: #3b82f6; margin-top: 15px; font-size: 24px; font-weight: 600; letter-spacing: 1px;">RAIL COMPASS</h1>
          </div>

          <h2 style="color: #f1f5f9; font-size: 20px; margin-bottom: 20px;">Password Reset Request</h2>

          <p style="color: #94a3b8; font-size: 16px; line-height: 1.6; margin-bottom: 30px; text-align: left;">
            We received a request to reset the password for your Rail Compass account.
            Click the button below to securely set up a new password. This link expires in 1 hour.
          </p>

          <a href="${resetUrl}" style="display: inline-block; background-color: #3b82f6; color: #ffffff; text-decoration: none; padding: 14px 28px; border-radius: 8px; font-weight: 600; font-size: 16px; margin-bottom: 30px; border: 1px solid #60a5fa;" clicktracking="off">
            Reset Password
          </a>

          <p style="color: #64748b; font-size: 14px; line-height: 1.5; margin-bottom: 0; text-align: left;">
            If you didn't request a password reset, you can safely ignore this email. Your password will not change until you access the link above and create a new one.
          </p>

          <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155;">
            <p style="color: #475569; font-size: 12px;">
              &copy; ${new Date().getFullYear()} Rail Compass. All rights reserved.
            </p>
          </div>

        </div>
      </div>
    `;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Rail Compass - Password Reset Request',
        html: message
      });
      return res.status(200).json(genericReply);
    } catch (err) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();
      console.error('Password reset email failed:', err.message);
      console.error('EMAIL_USER set:', !!process.env.EMAIL_USER, '| EMAIL_PASS set:', !!process.env.EMAIL_PASS);
      if (process.env.NODE_ENV !== 'production') {
        console.error(`🛠️  [DEV FALLBACK] Reset link: ${resetUrl}`);
      }
      return res.status(500).json({ success: false, message: 'We could not send the reset email right now. Please try again later.' });
    }
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const password = String(req.body.password || '');
    if (password.length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ success: false, message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
    }

    if (!(await ensureDb())) return dbUnavailable(res);

    const resetPasswordToken = crypto.createHash('sha256').update(String(req.params.token)).digest('hex');

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'This reset link is invalid or has expired. Please request a new one.' });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};
