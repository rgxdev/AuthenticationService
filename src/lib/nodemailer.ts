import nodemailer from 'nodemailer'
import {EMAIL_HOST, EMAIL_PASSWORD, EMAIL_PORT, EMAIL_USER} from "@/config/settings";

export default async function createTransporter() {
    return nodemailer.createTransport({
        port: Number(EMAIL_PORT), // default 587
        host: EMAIL_HOST,
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASSWORD,
        },
        secure: false,
        connectionTimeout: 10000,
    });
}
