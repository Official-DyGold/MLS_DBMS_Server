const passwordRules = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+[\]{};':"\\|,.<>/?-]).{8,}$/;

export default passwordRules;

export function generateOTP(length = 6): string {
  return Math.floor(Math.pow(10, length - 1) + Math.random() * 9 * Math.pow(10, length - 1)).toString();
}

export function isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

export function isValidPassword(password: string): boolean {
    return passwordRules.test(password);
}

export function isValidOTP(otp: string, userOTP: string): boolean {
    const otpRegex = /^\d{6}$/; // 6-digit OTP
    return otpRegex.test(otp) && otp === userOTP;
}

export function isOTPExpired(otpExpiryTime: Date): boolean {
    return new Date() > otpExpiryTime
}