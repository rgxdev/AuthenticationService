import {sendMail} from "@/utils/mailer";
import {DEFAULT_DOMAIN} from "@/config/settings";

export const sendPasswordResetEmail = async (email: string, token: string) => {
    const resetUrl = `${DEFAULT_DOMAIN}/reset-password?token=${token}`;

    const text = `Hallo,

Du hast eine Anfrage zum Zurücksetzen deines Passworts gestellt. Bitte klicke auf den folgenden Link, um dein Passwort zurückzusetzen:

${resetUrl}

Dieser Link ist 1 Stunde lang gültig.

Falls du keine Passwortänderung angefordert hast, ignoriere bitte diese E-Mail.

Viele Grüße,
Dein Team`

    const html = `<p>Hallo,</p>
<p>Du hast eine Anfrage zum Zurücksetzen deines Passworts gestellt. Bitte klicke auf den folgenden Link, um dein Passwort zurückzusetzen:</p>
<p><a href="${resetUrl}">Passwort zurücksetzen</a></p>
<p>Dieser Link ist 1 Stunde lang gültig.</p>
<p>Falls du keine Passwortänderung angefordert hast, ignoriere bitte diese E-Mail.</p>
<p>Viele Grüße,<br/>Dein Team</p>`;

    const mail = await sendMail(email, html, 'Passwort zurücksetzen', text);

};