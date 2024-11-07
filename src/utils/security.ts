import prisma from "@/lib/prismaClient";
import {NextFunction, Request, Response} from 'express';
import {logger} from "@/lib/logger";
import jwt from "jsonwebtoken";
import {generateRefreshToken, verifyTokenString} from "@/utils/essentials";
import {authenticator} from "otplib";
import {Device} from "@prisma/client";
import {REFRESH_TOKEN_EXPIRATION} from "@/config/settings";

interface TokenPayload extends jwt.JwtPayload {
    userId: string;
    username: string;
}

interface Roles {
    [key: string]: number;
}

const roles: Roles = {
    OWNER: 5,
    ADMIN: 4,
    DEVELOPER: 3,
    SUPPORTER: 2,
    USER: 1
};

export async function addOrUpdateDevice(user: any, req: Request): Promise<Device> {
    const ipAddress = req.header("CF-Connecting-IP") || req.ip || '0.0.0.0';
    const userAgent = req.headers['user-agent']?.substring(0, 256) || 'unknown';
    const fingerprint = req.body.fingerprint || null;

    try {
        let device;

        if (fingerprint) {
            device = await prisma.device.findFirst({
                where: {
                    userId: user.id,
                    fingerprint: fingerprint
                }
            });
        } else {
            device = await prisma.device.findFirst({
                where: {
                    userId: user.id,
                    ipAddress: ipAddress,
                    userAgent: userAgent
                }
            });
        }

        if (device) {
            device = await prisma.device.update({
                where: {id: device.id},
                data: {
                    userAgent: userAgent,
                    lastOnline: new Date(),
                    ipAddress: ipAddress
                }
            });
        } else {
            device = await prisma.device.create({
                data: {
                    userId: user.id,
                    ipAddress: ipAddress,
                    userAgent: userAgent,
                    fingerprint: fingerprint,
                    lastOnline: new Date()
                }
            });
        }

        return device;
    } catch (error: any) {
        logger.error("Failed to add/update device:", error, ipAddress);
        throw error;
    }
}

export const getUserDevices = async (req: Request, res: Response): Promise<Response> => {
    try {
        const token = req.headers['authorization'] ? verifyTokenString(req.headers['authorization'].split(' ')[1]) : null;
        if (!token || !token.userId) {
            return res.status(401).json({message: 'Unauthorized'});
        }

        const devices = await prisma.device.findMany({where: {userId: token.userId}});
        if (devices.length === 0) {
            return res.status(404).json({message: 'No devices found'});
        }

        logger.info('SYSTEM', `User ${token.userId} requested list of devices`);
        return res.status(200).json({devices});
    } catch (error: any) {
        logger.error("Error fetching user devices:", error);
        return res.status(500).json({message: 'Internal Server Error'});
    }
};


const checkUserRole = async (userId: string, requiredRole: string): Promise<{ status: number; message: string }> => {
    const user = await prisma.user.findUnique({where: {id: userId}});

    if (!user) {
        return {status: 404, message: "User not found"};
    }

    if (roles[user.role] < roles[requiredRole]) {
        return {status: 403, message: "Forbidden: insufficient permissions"};
    }

    return {status: 200, message: "Role check passed"};
};

export const authenticateToken = (requiredRole: string = "USER") => async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers['authorization'];
        const tempToken = authHeader?.split(' ')[1];
        if (!tempToken) {
            return res.status(401).json({message: "No token provided!"});
        }

        const decoded = verifyTokenString(tempToken) as TokenPayload | null;
        if (!decoded) {
            return res.status(403).json({message: "Invalid or expired token"});
        }

        const {userId} = decoded;

        if (requiredRole !== "USER") {
            const roleCheck = await checkUserRole(userId, requiredRole);
            if (roleCheck.status !== 200) {
                return res.status(roleCheck.status).json({message: roleCheck.message});
            }
        }

        const refreshToken = req.cookies['_auth.refresh-token'];
        if (!refreshToken) {
            return res.status(401).json({message: 'No refresh token provided.'});
        }

        const storedRefreshToken = await prisma.refreshToken.findUnique({
            where: {token: refreshToken},
            include: {user: true, device: true}
        });

        if (!storedRefreshToken || storedRefreshToken.userId !== userId) {
            return res.status(403).json({message: 'Invalid refresh token.'});
        }

        const currentTime = new Date();
        const timeLeft = storedRefreshToken.expiresAt.getTime() - currentTime.getTime();
        const fiveMinutes = 5 * 60 * 1000;

        if (timeLeft < fiveMinutes) {
            const newRefreshToken = generateRefreshToken();
            const newExpiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * REFRESH_TOKEN_EXPIRATION);

            await prisma.refreshToken.update({
                where: {token: refreshToken},
                data: {token: newRefreshToken, expiresAt: newExpiresAt}
            });

            res.cookie('_auth.refresh-token', newRefreshToken, {
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                expires: newExpiresAt,
                sameSite: 'lax'
            });

            logger.info("AUTH", `Refresh token renewed for userId: ${userId}`);
        }

        (req as any).userId = userId;

        next();
    } catch (error: any) {
        logger.warning("AUTH", "Invalid or expired token", undefined);
        return res.status(403).json({message: "Invalid or expired token"});
    }
};
type Verify2FAResult =
    | { type: 'invalid_request'; message: string }
    | { type: 'invalid_code'; message: string }
    | true;

export const verify2FACode = async (code: string, user: any): Promise<Verify2FAResult> => {
    if (!code || code.length !== 6 || !/^[0-9]+$/.test(code)) {
        return {type: 'invalid_request', message: 'Invalid 2FA code format.'};
    }

    if (!user.twoFactorSecret) {
        return {type: 'invalid_request', message: '2FA is not enabled for this account.'};
    }

    const isValid = authenticator.check(code, user.twoFactorSecret);
    if (!isValid) {
        return {type: 'invalid_code', message: 'Invalid 2FA code.'};
    }

    return true;
};