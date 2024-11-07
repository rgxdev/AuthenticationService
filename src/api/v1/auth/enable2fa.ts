import {Router} from "express";
import {authenticateToken} from "@/utils/security";
import {logger} from "@/lib/logger";
import prisma from "@/lib/prismaClient";
import {authenticator} from "otplib";
import qrcode from "qrcode";

export default (router: Router): void => {
    router.post("/enable-2fa", authenticateToken(), async (req, res) => {
        const userId = (req as any).userId;

        try {
            const user = await prisma.user.findUnique({
                where: {id: userId},
            });

            if (!user) {
                return res
                    .status(404)
                    .json({type: "invalid_request", message: "User not found."});
            }

            if (user.isTwoFactorEnabled) {
                return res.status(400).json({
                    type: "invalid_request",
                    message: "2FA is already enabled for this account.",
                });
            }

            const twoFactorSecret = authenticator.generateSecret(22);

            await prisma.user.update({
                where: {id: userId},
                data: {twoFactorSecret},
            });

            const otpauthUrl = authenticator.keyuri(
                user.email,
                "Schulsync",
                twoFactorSecret
            );

            const qrCodeBuffer = await qrcode.toBuffer(otpauthUrl);

            res.setHeader("Content-Type", "image/png");
            res.setHeader("Content-Length", qrCodeBuffer.length);

            res.send(qrCodeBuffer).status(201);
        } catch (error) {
            logger.error(
                "2FA_ENABLE",
                `Error enabling 2FA: ${error} | User ID: ${userId}`
            );
            return res
                .status(500)
                .json({type: "api_error", message: "Internal server error."});
        }
    });
};