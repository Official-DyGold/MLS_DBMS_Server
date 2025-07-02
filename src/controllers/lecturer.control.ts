import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { User, UserAttributes } from "../models/user.model";
import { config } from "../config";
import customResponse from "../utils/custom.reponse";
import { generateOTP } from '../utils/all.validator';
import { sendVerificationEmail } from "../services/email.service";

const JWT_SECRET = config.jwtSecret;
if (!JWT_SECRET) throw new Error("JWT_SECRET is not defined");

const JWT_REFRESH_SECRET = config.jwtRefreshSecret;
if (!JWT_REFRESH_SECRET) throw new Error("JWT_REFRESH_SECRET is not defined");

declare module 'express-serve-static-core' {
    interface Request {
        user?: UserAttributes
    }
}
