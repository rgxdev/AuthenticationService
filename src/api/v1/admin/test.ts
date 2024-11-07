import {Router} from "express";
import {authenticateToken} from "@/utils/security";
import {logger} from "@/lib/logger";

export default (router: Router): void => {
    router.post("/test", authenticateToken("ADMIN"), async (req, res) => {
        const userId = (req as any).userId;

        try {


            return res.status(200).json({type: "success", message: "2FA successfully enabled."});

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