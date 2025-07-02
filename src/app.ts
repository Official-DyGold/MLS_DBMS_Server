import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import authRoutes from './routes/auth.routes';
import adminRoutes from './routes/admin.routes';
import hodRoutes from './routes/hod.routes';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './docs/swagger';

const app = express();


app.use(cors());
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use('/api/auth', authRoutes)
app.use('/api/admin', adminRoutes)
app.use('/api/hod', hodRoutes)

app.get('/', (req, res) => {
  res.send('Multipurpose Database Management System Server is running!');
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

export default app;