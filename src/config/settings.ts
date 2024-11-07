import dotenv from 'dotenv';

dotenv.config();

// todo: change this to your own settings

export const API_VERSION = 'v1';
export const PORT = 1407;


export const ALLOWED_ORIGINS = ['http://localhost'];

export const LOGS_DIRECTORY = "/home/projects/log/schulsync";

export const COOKIE_DOMAIN = "schulsync.com";

export const AUTHENTICATION_TYPE = 1; // 1 = Email, 2 = Username
export const TOKEN_EXPIRATION = 30; // write it in days
export const REFERRAL_CODE_LENGTH = 6;
export const USERNAME_MIN_LENGTH = 3;
export const PASSWORD_MIN_LENGTH = 6;
export const MAX_IPS_PER_USER = 2; // So a ipaddress can register 2 accounts
export const MAX_DEVICES_PER_USER = 5; // So a user can login from 5 devices


export const REFRESH_TOKEN_EXPIRATION = 30; // write it in days


export const JWT_SECRET = process.env.JWT_SECRET!;

export const EMAIL_HOST = process.env.EMAIL_HOST!;
export let EMAIL_PORT = process.env.EMAIL_PORT! || 587;
export const EMAIL_USER = process.env.EMAIL_USER!;
export const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD!;