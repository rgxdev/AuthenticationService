// api/v1/auth/login.ts

import {Request, Response, Router} from 'express';
import {logger} from "@/lib/logger";
import {LoginSchema} from "@/schema/authSchema";
import prisma from "@/lib/prismaClient";
import {comparePassword, generateRefreshToken, generateTempToken, verifyTokenString} from "@/utils/essentials";
import {AUTHENTICATION_TYPE, REFRESH_TOKEN_EXPIRATION} from "@/config/settings";
import {addOrUpdateDevice} from "@/utils/security";

export default (router: Router) => {
    router.post('/login', async (req: Request, res: Response) => {
        let identifier;
        const {password} = req.body;
        const ipAddress = req.header("CF-Connecting-IP") || req.ip || '0.0.0.0';

        if (AUTHENTICATION_TYPE === 1) {
            identifier = req.body.email;
        } else if (AUTHENTICATION_TYPE === 2) {
            identifier = req.body.username;
        } else {
            logger.error("AUTH", `Invalid AUTHENTICATION_TYPE: ${AUTHENTICATION_TYPE}`);
            return res.status(500).json({type: 'server_error', message: "Server configuration is faulty."});
        }

        const validatedFields = LoginSchema.safeParse(req.body);
        if (!validatedFields.success) {
            logger.warning("AUTH", `Validation failed for login attempt with ${AUTHENTICATION_TYPE === 1 ? 'Email' : 'Username'}: ${identifier}`);
            return res.status(400).json({
                type: 'invalid_request',
                message: AUTHENTICATION_TYPE === 1 ? "Email and password are required." : "Username and password are required."
            });
        }

        logger.info("AUTH", `User login attempt with ${AUTHENTICATION_TYPE === 1 ? 'Email' : 'Username'}: ${identifier}`, ipAddress);

        try {
            const user = await prisma.user.findUnique({
                where: AUTHENTICATION_TYPE === 1 ? {email: identifier} : {username: identifier}
            });

            if (!user || !(await comparePassword(password, user.password))) {
                logger.warning("AUTH", `Invalid login attempt for ${AUTHENTICATION_TYPE === 1 ? 'Email' : 'Username'}: ${identifier}`, ipAddress);
                return res.status(401).json({type: 'invalid_request', message: "Incorrect login credentials."});
            }

            const updatedUser = await prisma.user.update({
                where: {id: user.id},
                data: {
                    lastLogin: new Date(),
                    firstLogin: user.firstLogin ? user.firstLogin : new Date()
                }
            });

            await addOrUpdateDevice(updatedUser, req);

            const tempToken = generateTempToken(updatedUser.id, updatedUser.username);
            const refreshToken = generateRefreshToken(updatedUser.id, updatedUser.username);

            await prisma.user.update({
                where: {id: user.id},
                data: {refreshToken}
            });

            res.cookie('_auth.refresh-token', refreshToken, {
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                /*domain: `.${COOKIE_DOMAIN}`,
                path: '/api/v1/auth/refresh',*/
                expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * REFRESH_TOKEN_EXPIRATION),
                sameSite: 'lax'
            });

            logger.info("AUTH", `User successfully logged in: ${identifier}`, ipAddress);

            return res.status(200).json({type: 'success', message: "Successfully logged in.", tempToken});
        } catch (error: any) {
            logger.error("Error during login process:", error);
            return res.status(500).json({type: 'api_error', message: "An error has occurred."});
        }
    });

    router.post('/refresh', async (req: Request, res: Response) => {
        const refreshToken = req.cookies['_auth.refresh-token'];
        if (!refreshToken) {
            return res.status(401).json({message: 'No refresh token provided.'});
        }

        try {
            const payload = verifyTokenString(refreshToken);
            if (!payload) {
                return res.status(403).json({message: 'Invalid refresh token.'});
            }

            const user = await prisma.user.findUnique({where: {id: payload.userId}});
            if (!user || user.refreshToken !== refreshToken) {
                return res.status(403).json({message: 'Invalid refresh token.'});
            }

            const tempToken = generateTempToken(user.id, user.username);
            const newRefreshToken = generateRefreshToken(user.id, user.username);

            await prisma.user.update({
                where: {id: user.id},
                data: {refreshToken: newRefreshToken}
            });

            res.cookie('_auth.refresh-token', newRefreshToken, {
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                /*domain: `.${COOKIE_DOMAIN}`,
                path: '/api/v1/auth/refresh',*/
                expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * REFRESH_TOKEN_EXPIRATION),
                sameSite: 'lax'
            });

            return res.status(200).json({tempToken});
        } catch (error: any) {
            logger.error("Error during token refresh:", error);
            return res.status(500).json({message: 'Internal Server Error'});
        }
    });
}