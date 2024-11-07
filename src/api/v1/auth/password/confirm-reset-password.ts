// src/routes/passwordReset.ts
import {Router} from "express";
import {logger} from "@/lib/logger";
import prisma from "@/lib/prismaClient";
import bcrypt from "bcrypt";

export default (router: Router): void => {
    router.post("/confirm-password-reset", async (req, res) => {
        const {token, newPassword, confirmPassword} = req.body;

        if (!token || !newPassword || !confirmPassword) {
            return res.status(400).json({
                type: "invalid_request",
                message: "Token, neues Passwort und Bestätigung sind erforderlich.",
            });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                type: "invalid_request",
                message: "Die neuen Passwörter stimmen nicht überein.",
            });
        }
        
        try {
            const resetTokenRecord = await prisma.resetToken.findUnique({
                where: {token},
                include: {user: true},
            });

            if (!resetTokenRecord) {
                return res.status(400).json({
                    type: "invalid_request",
                    message: "Ungültiger oder abgelaufener Token.",
                });
            }

            if (resetTokenRecord.expiresAt < new Date()) {
                return res.status(400).json({
                    type: "invalid_request",
                    message: "Der Token ist abgelaufen.",
                });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            await prisma.user.update({
                where: {id: resetTokenRecord.userId},
                data: {password: hashedPassword},
            });

            await prisma.resetToken.delete({
                where: {token},
            });

            logger.info(
                "ACCOUNT",
                `Password successfully reset | User ID: ${resetTokenRecord.userId}`
            );

            return res.status(200).json({
                type: "success",
                message: "Passwort erfolgreich zurückgesetzt.",
            });
        } catch (error) {
            logger.error(
                "ACCOUNT",
                `Error while resetting password | Error: ${error}`
            );
            return res
                .status(500)
                .json({type: "api_error", message: "Internal server error."});
        }
    });
};