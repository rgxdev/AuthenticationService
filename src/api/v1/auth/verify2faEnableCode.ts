import {Router} from 'express';
import prisma from "@/lib/prismaClient";
import {logger} from "@/lib/logger";
import {authenticateToken, verify2FACode} from "@/utils/security";

export default (router: Router) => {
    //@ts-ignore
    router.post('/verify-2fa-enable', authenticateToken(), async (req, res) => {
        const {twoFactorCode} = req.body;
        const userId = (req as any).userId;

        try {
            const user = await prisma.user.findUnique({
                where: {id: userId},
            });

            if (!user) {
                return res.status(404).json({type: 'invalid_request', message: 'Benutzer nicht gefunden.'});
            }

            if (user.isTwoFactorEnabled) {
                return res.status(400).json({
                    type: 'invalid_request',
                    message: '2FA ist bereits für dieses Konto aktiviert.'
                });
            }

            const verificationResult = await verify2FACode(twoFactorCode, user);
            if (verificationResult !== true) {
                return res.status(400).json({type: verificationResult.type, message: verificationResult.message});
            }

            await prisma.user.update({
                where: {id: userId},
                data: {isTwoFactorEnabled: true},
            });

            res.status(200).json({type: 'success', message: '2FA erfolgreich aktiviert.'});
        } catch (error) {
            logger.error('2FA_VERIFY_ENABLE', `Fehler bei der 2FA-Aktivierung: ${error} | Benutzer-ID: ${userId}`);
            return res.status(500).json({type: 'api_error', message: 'Interner Serverfehler.'});
        }
    });
};