import {
  Table,
  Column,
  Model,
  DataType,
  ForeignKey,
  BelongsTo,
  CreatedAt,
  UpdatedAt,
  PrimaryKey,
  Default,
} from 'sequelize-typescript';
import { User } from './user.model';

export interface PostAttributes {
  id?: string;
  creatorId: string;
  postTitle: string;
  postContent: string;
  excludeHOD: boolean,
  excludeLecturers: boolean;
  excludeStudents: boolean
  createdAt?: Date;
  updatedAt?: Date;
}

@Table({ tableName: 'posts', timestamps: true })
export class Post extends Model<PostAttributes> {
    @PrimaryKey
    @Default(DataType.UUIDV4)
    @Column({
        type: DataType.UUID,
    })
    id!: string;

    @ForeignKey(() => User)
    @Column({
        type: DataType.UUID,
        allowNull: false,
        onDelete: 'CASCADE',
    })
    creatorId!: string;

    @BelongsTo(() => User, 'creatorId')
    creator!: User;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    postTitle!: string;

    @Column({
        type: DataType.TEXT,
        allowNull: false,
    })
    postContent!: string;

    @Default(false)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    excludeLecturers!: boolean;

    @Default(false)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    excludeStudents!: boolean;

    @Default(false)
    @Column({
        type: DataType.BOOLEAN,
        allowNull: false
    })
    excludeHOD!: boolean;

    @CreatedAt
    @Default(DataType.NOW)
    @Column({
        type: DataType.DATE,
        allowNull: false,
    })
    createdAt!: Date;

    @UpdatedAt
    @Default(DataType.NOW)
    @Column({
        type: DataType.DATE,
        allowNull: false,
    })
    updatedAt!: Date;
}