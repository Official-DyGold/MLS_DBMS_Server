import { ErrorRequestHandler } from "express";
import multer from "multer";
import customResponse from "../utils/custom.response";

export const multerErrorHandler: ErrorRequestHandler = (err, req, res, next) => {
  if (
    err instanceof multer.MulterError ||
    (err.message && err.message.includes("Only image files"))
  ) {
    customResponse.errorResponse(res, "Critical Error", 400, { error: err.message });
    return;
  }

  // Pass error to next middleware if it's not a Multer error
  next(err);
};