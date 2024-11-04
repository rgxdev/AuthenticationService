import * as z from "zod";
import {PASSWORD_MIN_LENGTH, USERNAME_MIN_LENGTH} from "@/config/settings";


export const LoginSchema = z.object({
    email: z.string().email({
        message: "Email is required",
    }),
    password: z.string().min(1, {
        message: "Password is required",
    }),
    code: z.optional(z.string()),
});

export const RegisterSchema = z.object({
    email: z.string().email({
        message: "Email is required",
    }),
    username: z.string().min(USERNAME_MIN_LENGTH, {
        message: "Username is required",
    }),
    password: z.string().min(PASSWORD_MIN_LENGTH, {
        message: "Minimum 6 characters required",
    }),
    password_confirm: z.string().min(PASSWORD_MIN_LENGTH, {
        message: "Password confirmation is required",
    }),
});