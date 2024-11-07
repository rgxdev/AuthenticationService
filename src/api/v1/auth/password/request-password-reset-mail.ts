// src/routes/passwordReset.ts
import {Router} from "express";
import {logger} from "@/lib/logger";
import prisma from "@/lib/prismaClient";
import {sendPasswordResetEmail} from "@/emails/send-password-reset-mail";
import * as crypto from "node:crypto";

export default (router: Router): void => {
    router.post("/request-password-reset", async (req, res) => {
        const {email} = req.body;

        try {
            if (!email) {
                return res.status(400).json({
                    type: "invalid_request",
                    message: "Email is required.",
                });
            }
            const user = await prisma.user.findUnique({
                where: {email},
            });

            if (!user) {
                return res
                    .status(404)
                    .json({type: "invalid_request", message: "User not found."});
            }

            const resetToken = crypto.randomBytes(32).toString("hex");
            const resetTokenExpiry = new Date();
            resetTokenExpiry.setHours(resetTokenExpiry.getHours() + 1);

            await prisma.resetToken.create({
                data: {
                    token: resetToken,
                    userId: user.id,
                    expiresAt: resetTokenExpiry,
                },
            });

            await sendPasswordResetEmail(user.email, resetToken);

            logger.info(
                "ACCOUNT",
                `Password reset email sent | User ID: ${user.id}`
            );

            return res.status(200).json({
                type: "success",
                message: "Password reset email sent.",
            });
        } catch (error) {
            logger.error(
                "ACCOUNT",
                `Error while sending password reset email | EMAIL: ${email} | Error: ${error}`
            );
            return res
                .status(500)
                .json({type: "api_error", message: "Internal server error."});
        }
    });
};