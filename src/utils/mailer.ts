import createTransporter from "@/lib/nodemailer";
import {logger} from "@/lib/logger";


export async function sendMail(
    user: any,
    htmlContent: string,
    subject: string
) {
    try {
        const transporter = await createTransporter();

        const mailOptions = {
            from: "Schulsync System <no-reply@schulsync.com>", // todo: change this to your email
            to: user.email,
            subject: subject,
            html: htmlContent,
        };

        const result = await transporter.sendMail(mailOptions);
        logger.log("MAILER", `Email sent successfully to: ${result.accepted}`);
        return true;
    } catch (error) {
        logger.error("MAILER", `Failed to send email: ${(error as Error).message}`);
        return false;
    }
}
