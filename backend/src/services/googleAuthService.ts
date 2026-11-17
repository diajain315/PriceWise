import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prisma from '../utils/prisma';
import { env } from '../config/env';
import { HttpError } from '../utils/http';
import { signToken } from '../middlewares/auth';
import { publicUser } from '../controllers/authController';

export interface GoogleAuthPayload {
  credential?: string; // Google ID Token (from Google Identity Services)
  code?: string;       // Authorization Code (from OAuth 2.0 flow)
  redirectUri?: string;
  accessToken?: string;
}

export interface GoogleUserInfo {
  email: string;
  name: string;
  picture?: string;
  googleId: string;
}

/**
 * Verifies a Google ID Token using Google's public tokeninfo API
 */
export async function verifyGoogleIdToken(idToken: string): Promise<GoogleUserInfo> {
  const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
  if (!res.ok) {
    const errText = await res.text();
    throw new HttpError(401, `Invalid Google ID token: ${errText}`);
  }

  const payload: any = await res.json();
  if (!payload.email) {
    throw new HttpError(401, 'Google account has no associated email address.');
  }

  // Strictly verify audience if client ID is configured
  if (env.google.clientId) {
    const isMatchingAudience = payload.aud === env.google.clientId || payload.azp === env.google.clientId;
    if (!isMatchingAudience) {
      throw new HttpError(401, 'Unauthorized: Google ID token audience does not match server Client ID.');
    }
  }

  // Reject unverified email addresses from Google
  if (payload.email_verified === 'false' || payload.email_verified === false) {
    throw new HttpError(401, 'Unauthorized: Google account email address is not verified.');
  }

  return {
    email: payload.email.toLowerCase(),
    name: payload.name || payload.email.split('@')[0],
    picture: payload.picture,
    googleId: payload.sub,
  };
}

/**
 * Exchanges an authorization code for Google user details
 */
export async function exchangeGoogleCode(code: string, redirectUri: string): Promise<GoogleUserInfo> {
  if (!env.google.clientId || !env.google.clientSecret) {
    throw new HttpError(500, 'Google OAuth credentials (Client_ID and Client_secret) are not configured on the server.');
  }

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.google.clientId,
      client_secret: env.google.clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.text();
    throw new HttpError(401, `Failed to exchange Google authorization code: ${err}`);
  }

  const tokenData: any = await tokenRes.json();
  if (tokenData.id_token) {
    return verifyGoogleIdToken(tokenData.id_token);
  }

  // Fallback to userinfo endpoint using access_token
  const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });

  if (!userInfoRes.ok) {
    throw new HttpError(401, 'Failed to fetch user profile from Google.');
  }

  const userPayload: any = await userInfoRes.json();
  return {
    email: userPayload.email.toLowerCase(),
    name: userPayload.name || userPayload.email.split('@')[0],
    picture: userPayload.picture,
    googleId: userPayload.sub,
  };
}

/**
 * Verifies or decodes a Supabase JWT token and extracts user info
 */
export async function verifySupabaseToken(token: string): Promise<GoogleUserInfo | null> {
  // 1. If Supabase URL is available, verify cryptographically via Supabase auth API
  if (env.supabase.url) {
    try {
      const res = await fetch(`${env.supabase.url.replace(/\/+$/, '')}/auth/v1/user`, {
        headers: {
          Authorization: `Bearer ${token}`,
          apikey: env.supabase.anonKey,
        },
      });
      if (res.ok) {
        const data: any = await res.json();
        if (data?.email) {
          return {
            email: data.email.toLowerCase(),
            name: data.user_metadata?.full_name || data.user_metadata?.name || data.email.split('@')[0],
            picture: data.user_metadata?.avatar_url || data.user_metadata?.picture,
            googleId: data.user_metadata?.provider_id || data.id,
          };
        }
      }
    } catch {
      // Ignore network error and attempt fallback decode
    }
  }

  // 2. Fallback: inspect token payload if it was issued by Supabase
  try {
    const decoded: any = jwt.decode(token);
    if (decoded && (decoded.iss?.includes('supabase.co') || decoded.app_metadata?.provider === 'google') && decoded.email) {
      return {
        email: decoded.email.toLowerCase(),
        name: decoded.user_metadata?.full_name || decoded.user_metadata?.name || decoded.email.split('@')[0],
        picture: decoded.user_metadata?.avatar_url || decoded.user_metadata?.picture,
        googleId: decoded.user_metadata?.provider_id || decoded.sub,
      };
    }
  } catch {
    // Not a valid JWT
  }

  return null;
}

/**
 * Authenticates or auto-provisions a user account via Google OAuth
 */
export async function authenticateWithGoogle(payload: GoogleAuthPayload) {
  let googleUser: GoogleUserInfo | null = null;

  if (payload.credential) {
    try {
      googleUser = await verifyGoogleIdToken(payload.credential);
    } catch (err) {
      // If credential fails with Google tokeninfo, check if client sent a Supabase token
      const sbUser = await verifySupabaseToken(payload.credential);
      if (sbUser) {
        googleUser = sbUser;
      } else {
        throw err;
      }
    }
  } else if (payload.code) {
    const redirectUri = payload.redirectUri || 'http://localhost:5173/auth/callback';
    googleUser = await exchangeGoogleCode(payload.code, redirectUri);
  } else if (payload.accessToken) {
    // First, check if the accessToken is a Supabase token
    const sbUser = await verifySupabaseToken(payload.accessToken);
    if (sbUser) {
      googleUser = sbUser;
    } else {
      // Otherwise, query Google's userinfo endpoint
      const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${payload.accessToken}` },
      });
      if (!res.ok) throw new HttpError(401, 'Invalid Google access token.');
      const data: any = await res.json();
      googleUser = {
        email: data.email.toLowerCase(),
        name: data.name || data.email.split('@')[0],
        picture: data.picture,
        googleId: data.sub,
      };
    }
  } else {
    throw new HttpError(400, 'Missing Google credential or authorization code.');
  }

  if (!googleUser || !googleUser.email) {
    throw new HttpError(401, 'Failed to extract user profile from authentication token.');
  }

  // Find or create user in database
  let user = await prisma.user.findUnique({
    where: { email: googleUser.email },
  });

  if (!user) {
    // Generate secure random placeholder hash for OAuth user
    const dummyPassword = await bcrypt.hash(`GOOGLE_SSO_${Date.now()}_${Math.random()}`, 10);
    user = await prisma.user.create({
      data: {
        email: googleUser.email,
        name: googleUser.name,
        password: dummyPassword,
      },
    });
  } else if (user.password === 'GUEST_NO_PASSWORD') {
    // Claim guest placeholder account
    const dummyPassword = await bcrypt.hash(`GOOGLE_SSO_${Date.now()}_${Math.random()}`, 10);
    user = await prisma.user.update({
      where: { id: user.id },
      data: {
        name: googleUser.name || user.name,
        password: dummyPassword,
      },
    });
  }

  const token = signToken(user);
  return {
    token,
    user: publicUser(user),
  };
}
