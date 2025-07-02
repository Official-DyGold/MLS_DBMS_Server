import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';
import { config } from '../config';

function loadTemplate(templateName: string, replacements: Record<string, any>): string {
    const templatePath = path.join(__dirname, 'templates', templateName);
    let template = fs.readFileSync(templatePath, 'utf-8');

    Object.entries(replacements).forEach(([key, value]) => {
        template = template.replace(new RegExp(`{{${key}}}`, 'g'), value);
    });

    return template;
}

const transporter = nodemailer.createTransport({
    service: config.emailService,
    auth: {
        user: config.emailUser,
        pass: config.emailPassword,
    },
});

export const sendVerificationEmail = async (email: string, otp: string, expiryTime: string) => {
    const html = loadTemplate('verification_template.html', {
        otp,
        expiryTime: expiryTime,
        year: new Date().getFullYear(),
    });

    await transporter.sendMail({
        from: '"Computer Science Department" <no-reply@fedpolelCSC.com>',
        to: email,
        subject: 'Verify Your Departmental Account',
        html,
    });
};

export const sendResetPasswordEmail = async (email: string, otp: string, expiryTime: string) => {
    const html = loadTemplate('forget_password_temp.html', {
        otp,
        expiryTime: expiryTime,
        year: new Date().getFullYear(),
    });

    await transporter.sendMail({
        from: '"Computer Science Department" <no-reply@fedpolelCSC.com>',
        to: email,
        subject: 'Reset Your Departmental Password',
        html,
    });
};

export const sendWelcomeEmail = async (email: string) => {
    const html = loadTemplate('welcome_template.html', {
        email,
        year: new Date().getFullYear(),
    });

    await transporter.sendMail({
        from: '"Computer Science Department" <no-reply@fedpolelCSC.com>',
        to: email,
        subject: 'Welcome to the Computer Science Department',
        html,
    });
};

