import express, {Router} from 'express';
import {readdirSync} from 'fs';
import {join} from 'path';
import cors from "cors";
import expressUseragent from 'express-useragent';
import cookieParser from 'cookie-parser';
import {ALLOWED_ORIGINS, API_VERSION, PORT} from "@/config/settings";

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(expressUseragent.express());

const corsOptions = {
    origin: function (origin: any, callback: any) {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

const registerRoutesFromDirectory = async (directory: string, router: Router) => {
    const files = readdirSync(directory, {withFileTypes: true});

    for (const file of files) {
        const fullPath = join(directory, file.name);
        if (file.isDirectory()) {
            const newRouter = Router();
            router.use(`/${file.name}`, newRouter);
            await registerRoutesFromDirectory(fullPath, newRouter);
        } else if (file.name.endsWith('.ts')) {
            try {
                const routeModule = await import(fullPath);
                const route = routeModule.default;

                if (typeof route === 'function') {
                    route(router);
                    console.log(`${fullPath} loaded`);
                } else {
                    console.warn(`${fullPath} does not export a default function`);
                }
            } catch (error) {
                console.error(`Failed to load route at ${fullPath}:`, error);
            }
        }
    }
};

(async () => {
    const apiRouter = Router();
    await registerRoutesFromDirectory(join(__dirname, 'api', API_VERSION), apiRouter);
    app.use(`/`, apiRouter);

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
})();