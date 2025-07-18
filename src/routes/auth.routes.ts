
import express from 'express'
import { 
    createUser,
    resentOTP,
    OTPForPasswordReset,
    verifyOTP,
    verifyOTPForPassword,
    changePassword,
    userLogin,
    changePasswordWhenLoggedIn,
    getUserRole,
    updateUserProfile,
    getUserDetails,
    refreshToken,
} from '../controllers/auth.control'
import authMiddleware from '../middlewares/auth.middleware'
import { otpRateLimiter, loginOrRegisterRateLimiter } from '../middlewares/rate.limiter'
import { upload } from '../middlewares/upload.middleware'

const router = express.Router();

router.post('/register', loginOrRegisterRateLimiter, createUser)
router.post('/user-login', otpRateLimiter, userLogin)
router.post('/refresh-token', authMiddleware, refreshToken)
router.post('/request-otp', otpRateLimiter, resentOTP)
router.post('/request-password-reset', otpRateLimiter, OTPForPasswordReset)
router.post('/verify-otp', authMiddleware, verifyOTP)
router.post('/verify-password-otp', authMiddleware, verifyOTPForPassword)
router.post('/change-password', authMiddleware, changePassword)
router.post('/change-password-logged-in', authMiddleware, changePasswordWhenLoggedIn)
router.get('/get-user-role', authMiddleware, getUserRole)
router.get('/user/get-user-details', authMiddleware, getUserDetails)
router.put('/user/update-profile', authMiddleware, upload.single('profilePicture'), updateUserProfile)

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user and send OTP
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - lastName
 *               - userId
 *               - email
 *               - password
 *               - confirmPassword
 *             properties:
 *               firstName:
 *                 type: string
 *               middleName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               userId:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *               confirmPassword:
 *                 type: string
 *               isAdmin:
 *                 type: boolean
 *               isHOD:
 *                 type: boolean
 *               isLecturer:
 *                 type: boolean
 *               isStudent:
 *                 type: boolean
 *               isActive:
 *                 type: boolean
 *     responses:
 *       201:
 *         description: User created successfully and OTP sent
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: string
 *                         firstName:
 *                           type: string
 *                         middleName:
 *                           type: string
 *                         lastName:
 *                           type: string
 *                         userId:
 *                           type: string
 *                         isAdmin:
 *                           type: boolean
 *                         isAgent:
 *                           type: boolean
 *                         isCustomer:
 *                           type: boolean
 *                         isStudent:
 *                           type: boolean
 *                         isActive:
 *                           type: boolean
 *                     accessToken:
 *                       type: string
 *                     refreshToken:
 *                       type: string
 *       400:
 *         description: Bad request - missing fields or validation error
 *       500:
 *         description: Internal server error
 */

/**
 * @swagger
 * /api/auth/request-otp:
 *   post:
 *     summary: Resend OTP to user's email
 *     description: Resends a new OTP if the user exists, is not verified, and is active.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: OTP sent successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     otpToken:
 *                       type: string
 *                       description: Temporary OTP token
 *       400:
 *         description: User already verified
 *       403:
 *         description: User is not active
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/auth/request-password-reset:
 *   post:
 *     summary: Request OTP for password reset
 *     description: Sends a One-Time Password (OTP) to the user's email for password reset, valid for 15 minutes.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: OTP sent successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     otpToken:
 *                       type: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       400:
 *         description: User already verified
 *       403:
 *         description: User is not active
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/auth/verify-otp:
 *   post:
 *     summary: Verify OTP for account verifications
 *     description: Validates the OTP sent to the user's email. Marks user as verified if OTP is correct and not expired.
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - otp
 *             properties:
 *               otp:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: OTP verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: OTP verified successfully
 *                 data:
 *                   type: object
 *                   example: {}
 *       400:
 *         description: Bad request – missing or invalid OTP or expired
 *       401:
 *         description: Unauthorized – missing or invalid token
 *       404:
 *         description: User not found or OTP not set
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/auth//verify-password-otp:
 *   post:
 *     summary: Verify OTP for password reset
 *     description: Validates the OTP sent to the user's email. for changing of password.
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - otp
 *             properties:
 *               otp:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: OTP verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: OTP verified successfully
 *                 data:
 *                   type: object
 *                   example: {}
 *       400:
 *         description: Bad request – missing or invalid OTP or expired
 *       401:
 *         description: Unauthorized – missing or invalid token
 *       404:
 *         description: User not found or OTP not set
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/auth/change-password:
 *   post:
 *     summary: Change user password
 *     description: Allows a user to reset their password using a valid OTP token. Password must meet complexity requirements.
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - newPassword
 *               - confirmNewPassword
 *             properties:
 *               newPassword:
 *                 type: string
 *                 example: "NewP@ssw0rd!"
 *               confirmNewPassword:
 *                 type: string
 *                 example: "NewP@ssw0rd!"
 *     responses:
 *       200:
 *         description: Password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Password reset successfully
 *       400:
 *         description: Missing fields or password format invalid
 *       401:
 *         description: Missing or invalid authorization token
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /auth/change-password-logged-in:
 *   post:
 *     summary: Change password for logged-in user
 *     description: Changes the password for an authenticated user. The user must provide their current password along with the new password and its confirmation. The new password must meet complexity requirements.
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *               - confirmNewPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 example: "OldP@ssw0rd123"
 *               newPassword:
 *                 type: string
 *                 example: "NewP@ssw0rd456"
 *               confirmNewPassword:
 *                 type: string
 *                 example: "NewP@ssw0rd456"
 *     responses:
 *       200:
 *         description: Password changed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Password changed successfully
 *       400:
 *         description: Bad request – missing fields, password complexity issues, or passwords do not match
 *       401:
 *         description: Unauthorized – user not valid or not authenticated
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error while attempting to change password
 */

/**
 * @swagger
 * /api/auth/user-login:
 *   post:
 *     summary: User login
 *     description: Logs in an admin user by validating credentials. If the account is not verified, an OTP is sent instead. On successful login, access and refresh tokens are issued.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: admin@example.com
 *               password:
 *                 type: string
 *                 example: StrongP@ssw0rd
 *     responses:
 *       200:
 *         description: Login successful or OTP sent
 *         content:
 *           application/json:
 *             schema:
 *               oneOf:
 *                 - type: object
 *                   properties:
 *                     message:
 *                       type: string
 *                       example: Login successful
 *                     data:
 *                       type: object
 *                       properties:
 *                         user:
 *                           type: object
 *                           properties:
 *                             id:
 *                               type: string
 *                               example: "abc123"
 *                             email:
 *                               type: string
 *                               example: admin@example.com
 *                         accessToken:
 *                           type: string
 *                           example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *                         refreshToken:
 *                           type: string
 *                           example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *                 - type: object
 *                   properties:
 *                     message:
 *                       type: string
 *                       example: OTP sent successfully
 *                     data:
 *                       type: object
 *                       properties:
 *                         otpToken:
 *                           type: string
 *                           example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       400:
 *         description: Missing email or password
 *       401:
 *         description: Invalid credentials or not an admin
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/auth/get-user-role:
 *   get:
 *     summary: Get authenticated user roles
 *     description: Retrieves the roles of the authenticated user using the access token provided in the Authorization header.
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User role fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User role fetched successfully
 *                 status:
 *                   type: boolean
 *                   example: true
 *                 code:
 *                   type: integer
 *                   example: 200
 *                 data:
 *                   type: object
 *                   properties:
 *                     roles:
 *                       type: object
 *                       properties:
 *                         isAdmin:
 *                           type: boolean
 *                           example: true
 *                         isHOD:
 *                           type: boolean
 *                           example: false
 *                         isLecturer:
 *                           type: boolean
 *                           example: true
 *                         isStudent:
 *                           type: boolean
 *                           example: false
 *                         isActive:
 *                           type: boolean
 *                           example: true
 *       400:
 *         description: Access token is missing
 *       401:
 *         description: Authorization header is missing or invalid / Token invalid or expired
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/auth/user/update-profile:
 *   put:
 *     summary: Update user profile details
 *     description: Allows an authenticated user to update their profile information such as first name, middle name, last name, user ID, email, and optionally upload a profile picture. Only specified fields will be updated.
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *                 example: John
 *               middleName:
 *                 type: string
 *                 example: M
 *               lastName:
 *                 type: string
 *                 example: Doe
 *               userId:
 *                 type: string
 *                 example: A12345
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john.doe@example.com
 *               profilePicture:
 *                 type: string
 *                 format: binary
 *                 description: Upload a profile picture (image file)
 *     responses:
 *       200:
 *         description: User details updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User details updated successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: string
 *                           example: 3c9fd558-1a3c-4c4a-aef1-89fd3fbd9b7e
 *                         firstName:
 *                           type: string
 *                           example: John
 *                         middleName:
 *                           type: string
 *                           example: M
 *                         lastName:
 *                           type: string
 *                           example: Doe
 *                         userId:
 *                           type: string
 *                           example: A12345
 *                         email:
 *                           type: string
 *                           format: email
 *                           example: john.doe@example.com
 *                         profilePicture:
 *                           type: string
 *                           example: https://res.cloudinary.com/user/image/upload/v1750245256/defaultImage.jpg
 *                         updatedAt:
 *                           type: string
 *                           format: date-time
 *                           example: 2025-07-03T12:34:56.789Z
 *       400:
 *         description: No valid fields provided for update or access token missing
 *       401:
 *         description: Authorization header missing or invalid
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error or failed profile picture upload
 */

/**
 * @swagger
 * /api/auth/user/get-user-details:
 *   get:
 *     summary: Get authenticated user details
 *     description: Retrieves the details of the currently authenticated user including roles and status flags.
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User details fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User details fetched successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: integer
 *                           example: 123
 *                         firstName:
 *                           type: string
 *                           example: John
 *                         middleName:
 *                           type: string
 *                           example: M
 *                         lastName:
 *                           type: string
 *                           example: Doe
 *                         userId:
 *                           type: string
 *                           example: A12345
 *                         email:
 *                           type: string
 *                           format: email
 *                           example: john.doe@example.com
 *                         isAdmin:
 *                           type: boolean
 *                           example: true
 *                         isHOD:
 *                           type: boolean
 *                           example: false
 *                         isLecturer:
 *                           type: boolean
 *                           example: true
 *                         isStudent:
 *                           type: boolean
 *                           example: false
 *                         isActive:
 *                           type: boolean
 *                           example: true
 *                         isVerified:
 *                           type: boolean
 *                           example: true
 *                         createdAt:
 *                           type: string
 *                           format: date-time
 *                           example: 2025-07-03T12:34:56.789Z
 *                         updatedAt:
 *                           type: string
 *                           format: date-time
 *                           example: 2025-07-03T13:00:00.123Z
 *       400:
 *         description: Access token is missing
 *       401:
 *         description: Authorization header missing or invalid, or token expired/invalid
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error or JWT secret not configured
 */

/**
 * @swagger
 * /api/auth/refresh-token:
 *   post:
 *     summary: Refresh authentication tokens
 *     description: Issues a new access token and refresh token for an authenticated user, given a valid refresh token in the Authorization header.
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: false
 *     responses:
 *       200:
 *         description: Tokens refreshed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Tokens refreshed successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     accessToken:
 *                       type: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *                     refreshToken:
 *                       type: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       400:
 *         description: Refresh token is missing or invalid
 *       401:
 *         description: Authorization header missing or invalid / Token expired
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

export default router 