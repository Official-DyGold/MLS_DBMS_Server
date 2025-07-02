import { format } from 'path';
import swaggerJSDoc from 'swagger-jsdoc';

export const swaggerOptions: swaggerJSDoc.Options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'MPL DBMS API',
            version: '1.0.0',
            description: 'API documentation for the MPL Database Management System',
        },
        servers: [
            {
                url: 'http://localhost:5000', // Change this to your server URL
                description: 'Development server',
            },
            {
                url: 'https://mls-dbms-server.onrender.com', // Example server URL
                description: 'Production server',
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT', 
                },
            },
        },
        security: [
            {
                bearerAuth: [],
            },
        ],
    },
    apis: ['./src/routes/*.ts'], // Path to the API docs
};

export const swaggerSpec = swaggerJSDoc(swaggerOptions);