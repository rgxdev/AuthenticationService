// src/routes/passwordReset.ts
import {Router} from "express";
import {logger} from "@/lib/logger";
import prisma from "@/lib/prismaClient";
import bcrypt from "bcrypt";
import {authenticateToken} from "@/utils/security";

export default (router: Router): void => {
    router.post("/reset-password", authenticateToken(), async (req, res) => {
        const userId = (req as any).userId;

        const {oldPassword, newPassword, confirmPassword} = req.body;

        if (!oldPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({
                type: "invalid_request",
                message: "Altes, neues und Bestätigung Passwort sind erforderlich.",
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                type: "invalid_request",
                message: "Das neue Passwort muss mindestens 8 Zeichen lang sein."
            });
        }

        const user = await prisma.user.findUnique({
            where: {id: userId},
        });

        if (!user) {
            return res.status(404).json({
                type: "invalid_request",
                message: "Benutzer nicht gefunden.",
            });
        }

        const isPasswordSame = await bcrypt.compare(newPassword, user.password);

        if (isPasswordSame) {
            return res.status(400).json({
                type: "invalid_request",
                message: "Das neue Passwort kann nicht das gleiche wie das alte Passwort sein.",
            });
        }

        const isPasswordValid = await bcrypt.compare(oldPassword, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({
                type: "invalid_request",
                message: "Altes Passwort ist falsch.",
            });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                type: "invalid_request",
                message: "Die neuen Passwörter stimmen nicht überein.",
            });
        }


        try {

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            await prisma.user.update({
                where: {id: user.id},
                data: {password: hashedPassword},
            });


            logger.info(
                "ACCOUNT",
                `Password successfully changed | User ID: ${user.id}`
            );

            return res.status(200).json({
                type: "success",
                message: "Passwort erfolgreich geändert.",
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