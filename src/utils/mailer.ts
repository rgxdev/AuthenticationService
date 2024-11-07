import createTransporter from "@/lib/nodemailer";
import {logger} from "@/lib/logger";


export async function sendMail(
    email: string,
    htmlContent: string,
    subject: string,
    text?: string
) {
    try {
        const transporter = await createTransporter();

        const mailOptions = {
            from: "Personal System <no-reply@d-aaron.dev>", // todo: change this to your email
            to: email,
            subject: subject,
            html: htmlContent,
            text: text,
        };

        const result = await transporter.sendMail(mailOptions);
        logger.log("MAILER", `Email sent successfully to: ${result.accepted}`);
        return true;
    } catch (error) {
        logger.error("MAILER", `Failed to send email: ${(error as Error).message}`);
        return false;
    }
}
