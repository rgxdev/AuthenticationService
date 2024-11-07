// generate a endpoint that shows an html page

import {Router} from 'express';
import {logger} from '@/lib/logger';


export default (router: Router) => {
    router.get('/test', (req, res) => {
        logger.info('TEST', 'Test endpoint called');
        return res.send('<a href="otpauth://totp/Schulsync:hello%40d-aaron.dev?secret=IV6EG7CDGZZH2J2P&period=30&digits=6&algorithm=SHA1&issuer=Schulsync">Test endpoint</a>');
    });
};