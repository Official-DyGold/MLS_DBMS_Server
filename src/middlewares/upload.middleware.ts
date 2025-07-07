import multer from 'multer';
import { Request } from 'express';

const allowedMineTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp']

const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    if (allowedMineTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error("Only image files are allowed (jpeg, png, jpg, webp)"))
    }
};

const storage = multer.memoryStorage();

export const upload = multer({
    storage,
    limits: {
        fileSize: 2 * 1024 * 1024, // 2mb file size limit
    },
    fileFilter,
})