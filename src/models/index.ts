import { Sequelize } from 'sequelize-typescript';
import { User } from './user.model';
import { config } from '../config';
import { Post } from './post.model';

export const sequelize = new Sequelize({
    dialect: 'postgres',
    host: config.db.host,
    port: config.db.port,
    username: config.db.user,
    password: config.db.password,
    database: config.db.database,
    models: [User, Post], // Add your models here
    logging: false, // Disable logging for cleaner output
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: false, // This is for self-signed certificates
        },
    },
});
