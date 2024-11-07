// utils/security.ts

import prisma from "@/lib/prismaClient";
import {NextFunction, Request, Response} from 'express';
import {logger} from "@/lib/logger";
import jwt from "jsonwebtoken";
import {JWT_SECRET} from "@/config/settings";
import {verifyTokenString} from "@/utils/essentials";
import {authenticator} from "otplib";

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

export async function addOrUpdateDevice(user: any, req: Request): Promise<void> {
    const ipAddress = req.header("CF-Connecting-IP") || req.ip || '0.0.0.0';
    const userAgent = req.headers['user-agent']?.substring(0, 256) || 'unknown';

    try {
        const existingDevice = await prisma.device.findFirst({
            where: {
                userId: user.id,
                ipAddress: ipAddress
            }
        });

        if (existingDevice) {
            await prisma.device.update({
                where: {id: existingDevice.id},
                data: {
                    userAgent: userAgent,
                    lastOnline: new Date()
                }
            });
        } else {
            await prisma.device.create({
                data: {
                    userId: user.id,
                    ipAddress: ipAddress,
                    userAgent: userAgent,
                    lastOnline: new Date()
                }
            });
        }

    } catch (error: any) {
        logger.error("Failed to add/update device:", error, ipAddress);
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
        const token = authHeader?.split(' ')[1];

        if (!token) {
            return res.status(401).json({message: "No token provided!"});
        }

        const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
        const roleCheck = await checkUserRole(decoded.userId, requiredRole);

        if (roleCheck.status !== 200) {
            return res.status(roleCheck.status).json({message: roleCheck.message});
        }

        (req as any).userId = decoded.userId;
        next();

    } catch (error) {
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