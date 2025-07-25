import { 
    Table, 
    Column,
    Model,
    DataType,
    Default,
    PrimaryKey,
    HasMany
} from 'sequelize-typescript';
import { Post } from './post.model';

export interface UserAttributes {
    id?: string;
    profilePicture: string;
    firstName: string;
    middleName?: string;
    lastName: string;
    userId: string;
    email: string;
    password: string;
    isAdmin: boolean;
    isHOD: boolean;
    isLecturer: boolean;
    isStudent: boolean;
    isActive: boolean;
    isVerified: boolean
    otp?: string;
    otpExpiresAt?: Date;
    createdAt?: Date;
    updatedAt?: Date;
    deletedAt?: Date;
}

@Table({
    tableName: 'users',
    timestamps: true,
})
export class User extends Model<UserAttributes, UserAttributes> {
    @PrimaryKey
    @Default(DataType.UUIDV4)
    @Column({
        type: DataType.UUID,
        allowNull: false,
    })
    id!: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
        defaultValue: 'https://res.cloudinary.com/dat6vptxu/image/upload/v1750245256/defaultImage_dxivg3.jpg'
    })
    profilePicture!: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    firstName!: string;

    @Column({
        type: DataType.STRING,
        allowNull: true,
    })
    middleName?: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    lastName!: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
        unique: true
    })
    userId!: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
        unique: true
    })
    email!: string;

    @Column({
        type: DataType.STRING,
        allowNull: false
    })
    password!: string;

    @Default(false)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    isAdmin!: boolean;

    @Default(false)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    isHOD!: boolean;

    @Default(false)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    isLecturer!: boolean;

    @Default(false)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    isStudent!: boolean;

    @Default(true)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    isActive!: boolean;

    @Default(true)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    isVerified!: boolean;

    @Column({
        type: DataType.STRING,
        allowNull: true
    })
    otp?: string | null;

    @Column({
        type: DataType.DATE,
        allowNull: true
    })
    otpExpiresAt?: Date | null;

    @Default(DataType.NOW)
    @Column({
        type: DataType.DATE,
        allowNull: false
    })
    createdAt!: Date;

    @Default(DataType.NOW)
    @Column({
        type: DataType.DATE,
        allowNull: false
    })
    updatedAt!: Date;

    @Column({
        type: DataType.DATE,
        allowNull: true
    })
    deletedAt?: Date;

    @HasMany(() => Post, { foreignKey: "creatorId", as: "posts" })
    posts?: Post[];

    // Add any associations here if needed
    // For example, if you have a Profile model associated with User
    // profile?: Profile; // Uncomment if you have a Profile model
}
