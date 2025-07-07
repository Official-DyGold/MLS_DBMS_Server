import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import authRoutes from './routes/auth.routes';
import postRoutes from  './routes/post.routes';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './docs/swagger';
import { multerErrorHandler } from './middlewares/error.middleware'

const app = express();


app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use('/api/auth', authRoutes)
app.use('/api/posts', postRoutes)
app.use(multerErrorHandler)

app.get('/', (req, res) => {
  res.send('Multipurpose Database Management System Server is running!');
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

export default app;