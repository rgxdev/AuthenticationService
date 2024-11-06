import {Router} from 'express';
import prisma from "@/lib/prismaClient";
import {logger} from "@/lib/logger";
import {authenticateToken, verify2FACode} from "@/utils/security";

export default (router: Router) => {
    router.post('/verify-2fa', authenticateToken(), async (req, res) => {
        const {email, twoFactorCode} = req.body;

        try {
            if (!email) {
                return res.status(400).json({type: 'invalid_request', message: 'Email wird benötigt.'});
            }

            const user = await prisma.user.findUnique({
                where: {email},
            });

            if (!user) {
                return res.status(404).json({type: 'invalid_request', message: 'Benutzer nicht gefunden.'});
            }

            const verificationResult = await verify2FACode(twoFactorCode, user);

            if (verificationResult === true) {
                return res.status(200).json({type: 'success', message: '2FA erfolgreich verifiziert.'});
            } else {
                return res.status(400).json({type: verificationResult.type, message: verificationResult.message});
            }

        } catch (error) {
            logger.error('2FA_VERIFY', `Fehler bei der 2FA-Verifizierung: ${error}`);
            return res.status(500).json({type: 'api_error', message: 'Interner Serverfehler.'});
        }
    });
};