import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model";
import { config } from "../config";
import customResponse from "../utils/custom.response";
import { isValidOTP, isValidEmail, isValidPassword, generateOTP, isOTPExpired } from './../utils/all.validator';
import { sendWelcomeEmail, sendResetPasswordEmail, sendVerificationEmail } from "../services/email.service";
import { streamUpload } from "../utils/cloudinary.utils"

const JWT_SECRET = config.jwtSecret;
if (!JWT_SECRET) throw new Error("JWT_SECRET is not defined");

const JWT_REFRESH_SECRET = config.jwtRefreshSecret;
if (!JWT_REFRESH_SECRET) throw new Error("JWT_REFRESH_SECRET is not defined");

/* 
Create a new user (Admin, HOD, Lecturer, Student)
*/
export const createUser = async (req: Request, res: Response): Promise<void> => {
    const { firstName, middleName, lastName, userId, email, password, confirmPassword, isAdmin, isHOD, isLecturer, isStudent, isActive } = req.body;

    if (!firstName || !lastName || !userId || !email || !password) {
        customResponse.errorResponse(res, "All fields are required", 400, []);
        return;
    }

    if (!isValidEmail(email)) {
        customResponse.errorResponse(res, "Invalid email format", 400, []);
        return;
    }

    if (!isValidPassword(password)) {
        customResponse.errorResponse(res, "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character", 400, []);
        return;
    }

    if (password !== confirmPassword) {
        customResponse.errorResponse(res,  "Passwords do not match", 400, []);
        return;
    }

    try {
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            customResponse.errorResponse(res, "Email already exists", 400, []);
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const otp = generateOTP();
        const otpExpiresAt = new Date(Date.now() + 15 * 60 * 1000) // 15 minutes from now
        const otpExpiryTime = '15 Minutes'
        const newUser = await User.create({
            profilePicture: 'https://res.cloudinary.com/dat6vptxu/image/upload/v1750245256/defaultImage_dxivg3.jpg',
            firstName,
            middleName,
            lastName,
            userId,
            email,
            password: hashedPassword,
            isAdmin: isAdmin || false,
            isHOD: isHOD || false,
            isLecturer: isLecturer || false,
            isStudent: isStudent || false,
            isActive: isActive || true,
            isVerified: false,
            otp,
            otpExpiresAt,
        });
        await sendVerificationEmail(email, otp, otpExpiryTime);

        const accessToken = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET as string, { expiresIn: '1d' });
        const refreshToken = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_REFRESH_SECRET as string, { expiresIn: '7d' });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: config.env === 'production', // Use secure cookies in production
            sameSite: 'strict', // Adjust as necessary
            maxAge: 24 * 60 * 60 * 1000, // 1 day
        });

        customResponse.successResponse(res, 'User created successfully and OTP has been sent to your email', 201, {
            user: {
                id: newUser.id,
                firstName: newUser.firstName,  
                middleName: newUser.middleName,  
                lastName: newUser.lastName,
                userId: newUser.userId,    
                isAdmin: newUser.isAdmin,
                isAgent: newUser.isHOD,
                isCustomer: newUser.isLecturer,
                isStudent: newUser.isStudent,
                isActive: newUser.isActive,
            },
            accessToken: accessToken,
            refreshToken: refreshToken,
        })
        
    } catch (error) {
    customResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    return;
  }
}

/* 
This endpoint Resent OTP through users email
*/
export const resentOTP = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body

    try {
        const user = await User.findOne({ where: { email } });
         
        if (!user) {
            customResponse.errorResponse(res, 'User not found', 404, []);
            return;
        }

        if (!user.isActive) {
            customResponse.errorResponse(res, 'User is not active', 403, []);
            return;
        }

        if (user.isVerified) {
            customResponse.errorResponse(res, 'User has been verified', 400, []);
            return;
        }
        
        const otp = generateOTP();
        const otpExpiresAt = new Date(Date.now() + 15 * 60 * 1000)// 15 minutes from now
        const otpExpiryTime = '15 Minutes'

        user.otp = otp
        user.otpExpiresAt = otpExpiresAt
        await user.save();

        await sendVerificationEmail(email, otp, otpExpiryTime);
        
        const otpToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET as string, { expiresIn: '15m' });
       
        customResponse.successResponse(res, 'OTP sent successfully', 200,
            {
                otpToken: otpToken
            }
        );
    } catch (error) {
        customResponse.errorResponse(res, `Server Error ${ error }`, 500, []);
        return;
    }
};

/* 
resend OTP for Password Changing
*/
export const OTPForPasswordReset = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body

    try {
        const user = await User.findOne({ where: { email } });
         
        if (!user) {
            customResponse.errorResponse(res, 'User not found', 404, []);
            return;
        }

        if (!user.isActive) {
            customResponse.errorResponse(res, 'User is not active', 403, []);
            return;
        }

        if (!user.isVerified) {
            customResponse.errorResponse(res, 'Account not verified', 400, []);
            return;
        }
        
        const otp = generateOTP();
        const otpExpiresAt = new Date(Date.now() + 15 * 60 * 1000)// 15 minutes from now
        const otpExpiryTime = '15 Minutes'

        user.otp = otp
        user.otpExpiresAt = otpExpiresAt
        await user.save();

        await sendResetPasswordEmail(email, otp, otpExpiryTime);

        const otpToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET as string, { expiresIn: '15m' });
        
        customResponse.successResponse(res, 'OTP sent successfully', 200,
            {
                otpToken: otpToken
            }
        );
    } catch (error) {
        customResponse.errorResponse(res, `Server Error ${ error }`, 500, []);
        return;
    }
};

/* 
Verify OTP
*/
export const verifyOTP = async(req: Request, res: Response): Promise<void> => {
    const { otp } = req.body;

    try{
        if  (!otp) {
            customResponse.errorResponse(res, 'OTP is required', 400, []);
            return;
        }

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, []);
            return;
        }

        const otpToken = authHeader.split(' ')[1];
        if (!otpToken) {
            customResponse.errorResponse(res, 'OTP Token is missing', 400, []);
            return;
        }

        let email: string;
        const secret = JWT_SECRET;
        if (!secret) {
            customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
            return;
        }
        const decoded = jwt.verify(otpToken, secret) as { email: string };
        email = decoded.email

        const user = await User.findOne({ where: { email } })

        if (!user || !user.otp || !user.otpExpiresAt) {
            customResponse.errorResponse(res, 'Invalid OTP or User not found', 404, []);
            return;
        }

        if (!isValidOTP(otp, user.otp)) {
            customResponse.errorResponse(res, 'Invalid OTP', 400, []);
            return;
        }

        if (isOTPExpired(user.otpExpiresAt)) {

            user.otp = null;
            user.otpExpiresAt = null;
            await user.save();

            customResponse.errorResponse(res, 'OTP has expired', 400, []);
            return;
        }

        // OTP is valid, clear it
        user.otp = null;
        user.otpExpiresAt = null;
        user.isVerified = true; // Mark user as verified
        await user.save();

        await sendWelcomeEmail(email)

        customResponse.successResponse(res, "OTP verified successfully", 200, []);
        return;
    } catch (error) {
        customResponse.errorResponse(res, `Server Error ${ error }`, 500, []);
        return;
    }
}

/* 
Verify OTP for Password changing
*/
export const verifyOTPForPassword = async(req: Request, res: Response): Promise<void> => {
    const { otp } = req.body;

    try{
        if  (!otp) {
            customResponse.errorResponse(res, 'OTP is required', 400, []);
            return;
        }

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, []);
            return;
        }

        const otpToken = authHeader.split(' ')[1];
        if (!otpToken) {
            customResponse.errorResponse(res, 'OTP Token is missing', 400, []);
            return;
        }

        let email: string;
        const secret = JWT_SECRET;
        if (!secret) {
            customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
            return;
        }
        const decoded = jwt.verify(otpToken, secret) as { email: string };
        email = decoded.email

        const user = await User.findOne({ where: { email } })

        if (!user || !user.otp || !user.otpExpiresAt) {
            customResponse.errorResponse(res, 'Invalid OTP or User not found', 404, []);
            return;
        }

        if (!isValidOTP(otp, user.otp)) {
            customResponse.errorResponse(res, 'Invalid OTP', 400, []);
            return;
        }

        if (isOTPExpired(user.otpExpiresAt)) {

            user.otp = null;
            user.otpExpiresAt = null;
            await user.save();

            customResponse.errorResponse(res, 'OTP has expired', 400, []);
            return;
        }

        // OTP is valid, clear it
        user.otp = null;
        user.otpExpiresAt = null;
        await user.save();

        customResponse.successResponse(res, "OTP verified successfully", 200, []);
        return;
    } catch (error) {
        customResponse.errorResponse(res, `Server Error ${ error }`, 500, []);
        return;
    }
}

/**
 * Change password endpoint using OTP
 * This endpoint allows a user to change their password using an OTP sent to their email.
 */
export const changePassword = async (req: Request, res: Response): Promise<void> => {
    const {newPassword, confirmNewPassword} = req.body;

    try {

        if (!newPassword || !confirmNewPassword) {
        customResponse.errorResponse(res, 'All fields are required', 400, []);
        return;
        }

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, []);
            return;
        }

        const otpToken = authHeader.split(' ')[1];
        if (!otpToken) {
            customResponse.errorResponse(res, 'OTP Token is missing', 400, []);
            return;
        }

        let email: string;
        const secret = JWT_SECRET;
        if (!secret) {
            customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
            return;
        }
        const decoded = jwt.verify(otpToken, secret) as { email: string };
        email = decoded.email

        const user = await User.findOne({ where: { email } })

        if (!user) {
        customResponse.errorResponse(res, 'Invalid request', 404, []);
        return;
        }

        if (!isValidPassword(newPassword)) {
            customResponse.errorResponse(res, 'Password must be at least 8 characters and include uppercase, lowercase, number, and special character',
        400, [])
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        customResponse.errorResponse(res, 'Password reset successfully', 200, []);
        return;
    } catch (error) {
        customResponse.errorResponse(res, `Server Error ${ error }`, 500, []);
        return;
    }
}

/**
 * Reset password endpoint when user is logged in
 * This endpoint allows a user to change their password while logged in.
 */
export const changePasswordWhenLoggedIn = async (req: Request, res: Response): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, {});
        return;
    }

    const token = authHeader.split(" ")[1];
    let userId: string;

    try {
        const secret = JWT_SECRET;
        if (!secret) {
            customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
            return;
        }
        const decoded = jwt.verify(token, secret) as { id: string };
        userId = decoded.id;
    } catch (err) {
        customResponse.errorResponse(res, 'Invalid or expired token', 401, {});
        return;
    }

    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
        customResponse.errorResponse(res, 'All fields are required', 400, []);
    return;
    }

    if (currentPassword === newPassword) {
        customResponse.errorResponse(res, 'New Password is the same with old password', 400, []);
    return;
    }

    if (!isValidPassword(newPassword)) {
        customResponse.errorResponse(res,'Password must be at least 8 characters and include uppercase, lowercase, number, and special character', 400, []);
        return;
    }

    if (newPassword !== confirmNewPassword) {
        customResponse.errorResponse(res, 'New passwords do not match', 400, []);
    return;
    }

    try {
        const user =await User.findByPk(userId)

        if (!user) {
            customResponse.errorResponse(res, 'User not found', 404, {});
            return;
        }
        
        if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
            customResponse.errorResponse(res, 'Current password is incorrect', 400, []);
            return;
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedNewPassword;
        await user.save();

        customResponse.successResponse(res, 'Password changed successfully', 200, {});
        return;
    } catch (error) {
    customResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    return;
  }
}

export const userLogin = async (req: Request, res: Response): Promise<void> => {
    const { email, password } = req.body;

    if (!email || !password) {
        customResponse.errorResponse(res, 'All field are required', 400, [])
        return;
    }

    try {
        const user = await User.findOne({ where: { email } });
        if (!user) { 
            customResponse.errorResponse(res, 'User not found', 404, {});
            return;
        }

        const passwordValid = await bcrypt.compare(password, user.getDataValue('password'));
        if (!passwordValid) {
            customResponse.errorResponse(res, 'Invalid login details. This user is not an Admin', 401, {});
            return;
        }

        if (!user.isActive){
            customResponse.errorResponse(res, 'Invalid login details. This user is not an Active', 401, {});
            return;
        }

        if (!user.isVerified) {
            const otp = generateOTP();
            const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000)

            user.otp = otp
            user.otpExpiresAt = otpExpiresAt
            const otpExpiryTime = '15 Minutes'
            await user.save();

            await sendVerificationEmail(email, otp, otpExpiryTime)

            const secret = JWT_SECRET;
            if (!secret) {
                customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
                return;
            }
            const otpToken = jwt.sign({ id: user.id, email: user.email }, secret as string, { expiresIn: '15m' });
       
            customResponse.successResponse(res, 'OTP sent successfully', 200,
                {
                    otpToken: otpToken
                }
            );
            return;
        }

        const accessToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET as string, { expiresIn: '1d' });
        const refreshToken = jwt.sign({ id: user.id, email: user.email }, JWT_REFRESH_SECRET as string, { expiresIn: '7d' });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: config.env=== 'production', // Use secure cookies in production
            sameSite: 'strict', // Adjust as necessary
            maxAge: 24 * 60 * 60 * 1000, // 1 day
        });

        customResponse.successResponse(res, 'Login successful', 200, {
        user: {
            id: user.id,
            email: user.email,
        },
        accessToken: accessToken,
        refreshToken: refreshToken,
        });
        return;

    } catch (error) {
    customResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    return;
  }
}

/**
 * Verify user role using access token and return user's role
 */
export const getUserRole = async (req: Request, res: Response): Promise<void> => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, []);
        return;
    }

    const accessToken = authHeader.split(' ')[1];
    if (!accessToken) {
        customResponse.errorResponse(res, 'Access token is missing', 400, []);
        return;
    }

    try {
        const secret = JWT_SECRET;
        if (!secret) {
            customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
            return;
        }
        const decoded = jwt.verify(accessToken, secret) as { id: number, email: string };
        const user = await User.findByPk(decoded.id);

        if (!user) {
            customResponse.errorResponse(res, 'User not found', 404, []);
            return;
        }

        const roles = {
            isAdmin: user.isAdmin,
            isHOD: user.isHOD,
            isLecturer: user.isLecturer,
            isStudent: user.isStudent,
            isActive: user.isActive,
        };

        customResponse.successResponse(res, 'User role fetched successfully', 200, { roles });
    } catch (error) {
        customResponse.errorResponse(res, `Invalid or expired token: ${error}`, 401, []);
    }
};

/**
 * Update user profile and update the updatedAt timestamp
 */
export const updateUserProfile = async (req: Request, res: Response): Promise<void> => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, []);
        return;
    }

    const accessToken = authHeader.split(' ')[1];
    if (!accessToken) {
        customResponse.errorResponse(res, 'Access token is missing', 400, []);
        return;
    }

    try {
        const secret = JWT_SECRET;
        if (!secret) {
            customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
            return;
        }

        const decoded = jwt.verify(accessToken, secret) as { id: string, email: string };
        const user = await User.findByPk(decoded.id);

        if (!user) {
            customResponse.errorResponse(res, 'User not found', 404, []);
            return;
        }

        const allowedFields = ['firstName', 'middleName', 'lastName', 'userId', 'email'];
        let updated = false;

        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                (user as any)[field] = req.body[field];
                updated = true;
            }
        }

        if (req.file) {
            try {
                const uploadResult = await streamUpload(req.file.buffer);
                user.profilePicture = uploadResult.secure_url;
                updated = true
            } catch (uploadError) {
                customResponse.errorResponse(res, 'Failed to upload profile picture', 500, {});
                return;
            }
        }

        if (!updated) {
            customResponse.errorResponse(res, 'No valid fields provided for update', 400, []);
            return;
        }

        await user.save();

        customResponse.successResponse(res, 'User details updated successfully', 200, {
            user: {
                id: user.id,
                firstName: user.firstName,
                middleName: user.middleName,
                lastName: user.lastName,
                userId: user.userId,
                email: user.email,
                profilePicture: user.profilePicture,
                updatedAt: user.updatedAt
            }
        });
    } catch (error) {
        customResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    }
};

/**
 * Get user details using access token
 */
export const getUserDetails = async (req: Request, res: Response): Promise<void> => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, []);
        return;
    }

    const accessToken = authHeader.split(' ')[1];
    if (!accessToken) {
        customResponse.errorResponse(res, 'Access token is missing', 400, []);
        return;
    }

    try {
        const secret = JWT_SECRET;
        if (!secret) {
            customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
            return;
        }
        const decoded = jwt.verify(accessToken, secret) as { id: number, email: string };
        const user = await User.findByPk(decoded.id);

        if (!user) {
            customResponse.errorResponse(res, 'User not found', 404, []);
            return;
        }

        const roles: Record<string, boolean> = {};
        if (user.isAdmin) roles.isAdmin = true;
        if (user.isHOD) roles.isHOD = true;
        if (user.isLecturer) roles.isLecturer = true;
        if (user.isStudent) roles.isStudent = true;

        customResponse.successResponse(res, 'User details fetched successfully', 200, {
            user: {
                id: user.id,
                profilePicture: user.profilePicture,
                firstName: user.firstName,
                middleName: user.middleName,
                lastName: user.lastName,
                userId: user.userId,
                email: user.email,
                ...roles, // Only true roles will be included
                isActive: user.isActive,
                isVerified: user.isVerified,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            }
        });
    } catch (error) {
        customResponse.errorResponse(res, `Invalid or expired token: ${error}`, 401, []);
    }
};

/**
 * Refresh access token using refresh token cookie
 */
export const refreshToken = async (req: Request, res: Response): Promise<void> => {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
        customResponse.errorResponse(res, 'Refresh token is missing', 401, {});
        return;
    }

    try {
        const secret = JWT_REFRESH_SECRET;
        if (!secret) {
            customResponse.errorResponse(res, 'JWT refresh secret is not configured', 500, {});
            return;
        }
        const decoded = jwt.verify(refreshToken, secret) as { id: number, email: string };

        const user = await User.findByPk(decoded.id);
        if (!user) {
            customResponse.errorResponse(res, 'User not found', 404, {});
            return;
        }

        if (!user.isActive) {
            customResponse.errorResponse(res, 'User is not active', 403, {});
            return;
        }

        const newAccessToken = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET as string,
            { expiresIn: '1d' }
        );

        customResponse.successResponse(res, 'Access token refreshed successfully', 200, {
            accessToken: newAccessToken
        });
    } catch (error) {
        customResponse.errorResponse(res, `Invalid or expired refresh token: ${error}`, 401, {});
    }
};