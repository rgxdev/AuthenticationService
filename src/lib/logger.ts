import * as fs from 'fs';
import * as path from 'path';
import {LOGS_DIRECTORY} from "@/config/settings";

class Logger {
    private static logDirectory = path.join(LOGS_DIRECTORY);
    private static logFile = path.join(Logger.logDirectory, `${new Date().toISOString().split('T')[0]}.txt`);

    public static log(category: string, message: string, ip?: string): void {
        Logger.writeLog('LOG', '32', category, message, ip);
    }

    public static error(category: string, message: string, ip?: string): void {
        Logger.writeLog('ERROR', '31', category, message, ip);
    }

    public static warning(category: string, message: string, ip?: string): void {
        Logger.writeLog('WARNING', '33', category, message, ip);
    }

    public static info(category: string, message: string, ip?: string): void {
        Logger.writeLog('INFO', '34', category, message, ip);
    }

    private static ensureLogFile(): void {
        if (!fs.existsSync(Logger.logDirectory)) {
            fs.mkdirSync(Logger.logDirectory, {recursive: true});
        }
        if (!fs.existsSync(Logger.logFile)) {
            fs.writeFileSync(Logger.logFile, `Initialized on ${new Date().toISOString()}\n`, {flag: 'wx'});
        }
    }

    private static writeLog(level: string, color: string, category: string, message: string, ip?: string): void {
        const formattedMessage = Logger.formatMessage(level, color, category, message, ip);
        console.log(formattedMessage);
        Logger.ensureLogFile();
        fs.appendFileSync(Logger.logFile, `${formattedMessage.replace(/\x1b\[[0-9]+m/g, '')}\n`);
    }

    private static getTimeStamp(): string {
        const now = new Date();
        return now.toLocaleTimeString('de-DE', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    }

    private static formatMessage(level: string, color: string, category: string, message: string, ip?: string): string {
        const timestamp = Logger.getTimeStamp();
        const ipPart = ip ? ` | IP: ${ip}` : '';
        return `\x1b[${color}m${timestamp} | ${category} | ${message}${ipPart}\x1b[0m`;
    }
}

export const logger = Logger;