import {Router} from "express";

const motivationalSentences = [
    "Believe in yourself!",
    "You can do it!",
    "Stay positive and happy.",
    "Never give up!",
    "Work hard, dream big.",
    "Stay strong, stay positive.",
    "You are capable of amazing things.",
    "Dream it. Believe it. Achieve it.",
    "Keep pushing forward.",
    "Stay focused and never give up.",
    "Believe you can and you're halfway there.",
    "Push yourself, because no one else is going to do it for you.",
    "The harder you work for something, the greater you’ll feel when you achieve it.",
    "Don’t stop when you’re tired. Stop when you’re done.",
    "Success doesn’t just find you. You have to go out and get it.",
    "Dream bigger. Do bigger.",
    "Wake up with determination. Go to bed with satisfaction.",
    "Do something today that your future self will thank you for.",
    "Little things make big days.",
    "It’s going to be hard, but hard does not mean impossible.",
];

export default (router: Router) => {
    router.get("/", (req, res) => {
        res.setHeader(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, proxy-revalidate"
        );
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
        res.setHeader("Surrogate-Control", "no-store");

        const randomSentence =
            motivationalSentences[
                Math.floor(Math.random() * motivationalSentences.length)
                ];

        res.json({message: randomSentence});
    });
};
