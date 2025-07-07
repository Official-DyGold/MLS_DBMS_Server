import cloudinary from 'cloudinary'
import streamifier from 'streamifier'
import { config as cloudConfig } from '../config'

cloudinary.v2.config({
  cloud_name: cloudConfig.cloudinaryName,
  api_key: cloudConfig.cloudinaryApiKey,
  api_secret: cloudConfig.cloudinaryApiSecret,
})

export const streamUpload = (fileBuffer: Buffer): Promise<any> => {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.v2.uploader.upload_stream({ folder: 'mlForDBMS_Files'  }, (error, result) => {
            if (result) resolve(result);
            else reject(error)
        });
        streamifier.createReadStream(fileBuffer).pipe(stream)
    });
}