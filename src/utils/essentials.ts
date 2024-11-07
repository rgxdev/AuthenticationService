import bcrypt from 'bcrypt';
import jwt, {JwtPayload} from 'jsonwebtoken';
import {Request} from 'express';
import {logger} from '@/lib/logger';
import {COOKIE_DOMAIN, JWT_SECRET, REFERRAL_CODE_LENGTH} from "@/config/settings";
import {randomBytes} from "crypto";
import prisma from "@/lib/prismaClient";

export interface TokenPayload extends JwtPayload {
    userId: string;
    username: string;
}

export const hashPassword = async (password: string) => bcrypt.hash(password, 10);

export const comparePassword = async (password: string, hashed: string) => {
    try {
        return await bcrypt.compare(password, hashed);
    } catch (error: any) {
        logger.error('Error comparing password:', error);
        return false;
    }
};

export const generateTempToken = (userId: string, username: string) => {
    return jwt.sign({userId, username}, JWT_SECRET, {
        expiresIn: '15m',
        audience: `.${COOKIE_DOMAIN}`,
    });
};

export const generateRefreshToken = () => {
    return randomBytes(64).toString('hex');
};

export function generateRandomString(length: number) {
    const CHARACTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({length}, () => CHARACTERS.charAt(Math.floor(Math.random() * CHARACTERS.length))).join('');
}

export const extractTokenFromRequest = (req: Request): string | null => {
    const AUTH_HEADER = req.headers["authorization"];
    if (!AUTH_HEADER) return null;
    const token = AUTH_HEADER.split(" ")[1];
    return token || null;
};

export const decodeUserTokenByRequest = async (
    req: Request
): Promise<TokenPayload | null> => {
    const TOKEN = extractTokenFromRequest(req);
    if (!TOKEN) return null;
    return verifyTokenString(TOKEN);
};

export const verifyTokenString = (token: string): TokenPayload | null => {
    try {
        return jwt.verify(token, JWT_SECRET) as TokenPayload;
    } catch {
        return null;
    }
};

export const generateReferralCode = () => {
    return randomBytes(REFERRAL_CODE_LENGTH).toString('hex');
};

export const generateSsoToken = async (userId: string) => {
    const token = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 30);

    await prisma.ssoToken.create({
        data: {
            userId,
            token,
            expiresAt,
        },
    });

    return token;
};