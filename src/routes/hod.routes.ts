import express from 'express'
/* import { 
    
} from '../controllers/hod.control' */
import authMiddleware from '../middlewares/auth.middleware'
import { otpRateLimiter } from '../middlewares/rate.limiter'

const router = express.Router();


export default router