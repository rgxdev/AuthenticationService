import {Request, Response, Router} from 'express';
import {logger} from "@/lib/logger";
import {LoginSchema} from "@/schema/authSchema";
import prisma from "@/lib/prismaClient";
import {comparePassword, generateRefreshToken, generateTempToken} from "@/utils/essentials";
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

            const device = await addOrUpdateDevice(updatedUser, req);

            const tempToken = generateTempToken(updatedUser.id, updatedUser.username);
            const mainToken = generateRefreshToken();
            const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * REFRESH_TOKEN_EXPIRATION);

            await prisma.refreshToken.create({
                data: {
                    token: mainToken,
                    userId: user.id,
                    deviceId: device.id,
                    expiresAt
                }
            });

            res.cookie('_auth.refresh-token', mainToken, {
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
            const storedToken = await prisma.refreshToken.findUnique({
                where: {token: refreshToken},
                include: {user: true, device: true}
            });

            if (!storedToken || storedToken.expiresAt < new Date()) {
                return res.status(403).json({message: 'Invalid or expired refresh token.'});
            }

            const tempToken = generateTempToken(storedToken.user.id, storedToken.user.username);
            const newRefreshToken = generateRefreshToken();
            const newExpiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * REFRESH_TOKEN_EXPIRATION);

            await prisma.refreshToken.update({
                where: {token: refreshToken},
                data: {token: newRefreshToken, expiresAt: newExpiresAt}
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