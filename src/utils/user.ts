import {Request, Response} from "express";
import prisma from "@/lib/prismaClient";
import {decodeUserTokenByRequest, TokenPayload} from "@/utils/essentials";
import jwt from 'jsonwebtoken';
import {JWT_SECRET} from '@/config/settings';
import {logger} from '@/lib/logger';


export const getUserByRequest = async (req: Request) => {
    const TOKEN_DATA = await decodeUserTokenByRequest(req);
    if (!TOKEN_DATA) return null;

    const user = await prisma.user.findUnique({
        where: {id: TOKEN_DATA.userId},
    });
    if (!user) return null;

    return user;
};

export const getToken = (req: Request, res: Response): TokenPayload | undefined => {
    const AUTH_HEADER = req.headers['authorization'];
    const TOKEN = AUTH_HEADER?.split(' ')[1];

    if (!TOKEN) {
        res.status(400).json({type: 'invalid_request', message: 'No Token provided'});
        return undefined;
    }

    try {
        return jwt.verify(TOKEN, JWT_SECRET) as TokenPayload;
    } catch (err) {
        res.status(401).json({type: 'api_error', message: 'Invalid or expired token'});
        return undefined;
    }
};

export const verifyToken = (req: Request, res: Response) => {
    const TOKEN = getToken(req, res);

    if (!TOKEN || !TOKEN.userId) {
        return res.status(403).json({type: 'invalid_request', message: 'Invalid or expired token', valid: false});
    }

    return res.status(200).json({type: 'success', message: 'Token valid', valid: true});
};

export const verifyUserAccount = async (req: Request, res: Response) => {
    try {
        const {key} = req.query;
        const VERIFY_KEY_RECORD = await prisma.verifyKey.findUnique({
            where: {key: key as string},
            include: {user: true},
        });

        if (!VERIFY_KEY_RECORD || VERIFY_KEY_RECORD.expiresAt < new Date()) {
            return res.status(400).json({type: 'invalid_request', message: 'Token is invalid or has expired'});
        }

        await prisma.verifyKey.delete({where: {id: VERIFY_KEY_RECORD.id}});

        try {
            logger.info('Whitelist verification email sent to:', VERIFY_KEY_RECORD.user.email);
        } catch {
            logger.error('MAILER', `Failed to send verification email: ${VERIFY_KEY_RECORD.user.email}`);
        }

        return res.status(200).send({type: 'invalid_request', message: 'Email verified successfully'});
    } catch {
        return res.status(500).send({type: 'api_error', message: 'Failed to verify email'});
    }
};

export const returnUserByRequest = async (req: Request, res: Response) => {
    try {
        const TOKEN = getToken(req, res);
        if (!TOKEN || !TOKEN.userId) return res.status(401).json({type: 'invalid_request', message: 'Unauthorized'});

        const USER = await prisma.user.findUnique({where: {id: TOKEN.userId}});
        if (!USER) return res.status(404).json({type: 'invalid_request', message: 'User not found'});

        const userDetails = {
            id: USER.id,
            email: USER.email,
            createdAt: USER.createdAt,
            role: USER.role,
            isTwoFactorEnabled: USER.isTwoFactorEnabled,
            nickname: USER.nickname
        };

        return res.status(200).json({type: 'success', data: userDetails});
    } catch {

        return res.status(500).json({type: 'api_error', message: 'Internal Server Error'});
    }
};

export async function addNewDevice(user: any, req: Request) {
    const ipAddress = req.header("CF-Connecting-IP") || req.ip || '0.0.0.0';
    const userAgent = req.headers['user-agent'] || 'unknown';

    try {
        let DEVICE = await prisma.device.findFirst({
            where: {ipAddress: ipAddress}
        });
        if (!DEVICE) {
            DEVICE = await prisma.device.create({
                data: {
                    userId: user.id,
                    ipAddress: ipAddress,
                    userAgent: userAgent,
                    lastOnline: new Date()
                }
            });
        } else {
            DEVICE = await prisma.device.update({
                where: {id: DEVICE.id},
                data: {
                    userAgent: userAgent,
                    lastOnline: new Date()
                }
            });
        }
    } catch (error) {
        console.error("Failed to add device: ", error);
    }
}