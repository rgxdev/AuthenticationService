// register.ts
import {Request, Response, Router} from 'express';
import {logger} from "@/lib/logger";
import {RegisterSchema} from "@/schema/authSchema";
import prisma from "@/lib/prismaClient";
import {generateRandomString, generateReferralCode, generateToken, hashPassword} from "@/utils/essentials";
import {AUTHENTICATION_TYPE, COOKIE_DOMAIN, MAX_IPS_PER_USER, TOKEN_EXPIRATION} from "@/config/settings";
import {sendMail} from "@/utils/mailer";

export default (router: Router) => {
    // @ts-ignore
    router.post('/register', async (req: Request, res: Response) => {
        const {username, email, password, password_confirm} = req.body;
        const ipAddress = req.header("CF-Connecting-IP") || req.ip || '0.0.0.0';
        const referralCode = req.cookies.referralCode || req.body.referralCode;


        const validatedFields = RegisterSchema.safeParse(req.body);
        if (!validatedFields.success) {
            logger.warning("AUTH", `Validation failed for registration with Email: ${email}`, ipAddress);
            return res.status(400).json({
                type: 'invalid_request',
                message: "All fields are required and must be valid."
            });
        }

        const existingRegistration = await prisma.user.findMany({
            where: {ip: ipAddress},
        });

        if (existingRegistration.length >= MAX_IPS_PER_USER) {
            return res.status(400).json({type: 'invalid_request', message: 'IP address is already registered'});
        }

        if (password !== password_confirm) {
            logger.warning("AUTH", `Password confirmation failed for Email: ${email}`, ipAddress);
            return res.status(400).json({type: 'invalid_request', message: "Passwords do not match."});
        }

        try {
            const existingUser = await prisma.user.findUnique({
                where: AUTHENTICATION_TYPE === 1 ? {email: email} : {username: username}
            });

            if (existingUser) {
                logger.warning("AUTH", `Registration attempt with existing ${AUTHENTICATION_TYPE === 1 ? 'Email' : 'Username'}: ${AUTHENTICATION_TYPE === 1 ? email : username}`, ipAddress);
                return res.status(400).json({
                    type: 'invalid_request',
                    message: `This ${AUTHENTICATION_TYPE === 1 ? 'Email' : 'Username'} is already registered.`
                });
            }

            const hashedPassword = await hashPassword(password);

            const transactionResult = await prisma.$transaction(async (prisma) => {
                const newUser = await prisma.user.create({
                    data: {
                        username,
                        email,
                        password: hashedPassword,
                        ip: ipAddress,
                        referralCode: generateReferralCode()
                    }
                });

                if (referralCode) {
                    const referrer = await prisma.user.findUnique({
                        where: {referralCode},
                    });

                    if (referrer) {
                        await prisma.user.update({
                            where: {id: newUser.id},
                            data: {referredBy: referrer.id},
                        });

                        await prisma.referral.create({
                            data: {
                                referrerId: referrer.id,
                                referredUserId: newUser.id,
                            },
                        });
                    }
                }

                const verifyKey = await prisma.verifyKey.create({
                    data: {
                        key: generateRandomString(10),
                        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 5),
                        ip: ipAddress,
                        userId: newUser.id,
                    },
                });

                const mailStatus = await sendMail(newUser, verifyKey.key, 'Verify your Schulsync Account');

                if (!mailStatus) {
                    logger.error('MAILER', `Failed to send verification email: ${email}`);
                    throw new Error("Failed to send verification email.");
                }
                return {newUser, verifyKey};
            });

            const token = generateToken(transactionResult.newUser.id, transactionResult.newUser.username);

            res.cookie('_auth.session-token', token, {
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                domain: `.${COOKIE_DOMAIN}`,
                path: '/',
                expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * TOKEN_EXPIRATION),
                sameSite: 'lax'
            });

            logger.info("AUTH", `New user registered and logged in: ${AUTHENTICATION_TYPE === 1 ? email : username}`, ipAddress);

            return res.status(201).json({type: 'success', message: "Registration successful."});
        } catch (error: any) {
            logger.error("Error during registration process:", error, ipAddress);
            return res.status(500).json({type: 'api_error', message: `An error has occurred. ${error.message}`});
        }
    });
};