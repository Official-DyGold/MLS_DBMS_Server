import app from './app';
import { sequelize } from './models';
import { config } from './config';

const PORT = config.port || 5000;

//Retry connection to the database
async function connectWithRetry(retries = 5, delay = 3000) {
    for (let i = 0; i < retries; i++) {
        try {
            await sequelize.authenticate();
            await sequelize.sync({ alter: true });
            return;
        } catch (err) {
            console.error('Database connection failed:', err);
            if (i < retries - 1) {
                await new Promise((res) => setTimeout(res, delay));
            } else {
                throw err;
            }
        }
    }
};

async function startServer() {
    try {
        await connectWithRetry();

        // Start the server
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (err) {
        console.error('Failed to connect to the database:', err);
        process.exit(1); // Exit the process with failure
    }
}

startServer()