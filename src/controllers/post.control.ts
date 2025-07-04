import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { Post } from '../models/post.model';
import { config } from "../config";
import { User } from '../models/user.model';
import customResponse from "../utils/custom.response";
import { Op } from 'sequelize';

const JWT_SECRET = config.jwtSecret;
if (!JWT_SECRET) throw new Error("JWT_SECRET is not defined");

const JWT_REFRESH_SECRET = config.jwtRefreshSecret;
if (!JWT_REFRESH_SECRET) throw new Error("JWT_REFRESH_SECRET is not defined");

/* 
This endpoint create a post
*/
export const createPost = async (req: Request, res: Response): Promise<void> => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
      customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, []);
      return;
  }

  const accessToken = authHeader.split(' ')[1];
  if (!accessToken) {
      customResponse.errorResponse(res, 'Access token is missing', 400, []);
      return;
  }

  let creatorId: string;

  try {
    
    const secret = JWT_SECRET;
    if (!secret) {
        customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
        return;
    }
    const decoded = jwt.verify(accessToken, secret) as { id: string };
    creatorId = decoded.id;
  } catch (err) {
    customResponse.errorResponse(res, 'Invalid or expired token', 401, {});
    return;
  }

  try {
    const {
      postTitle,
      postContent,
      excludeLecturers,
      excludeStudents,
      excludeHOD
    } = req.body;

    if (!postTitle || !postContent) {
      customResponse.errorResponse(res, 'Title and content are required', 400, {});
      return;
    }

    const newPost = await Post.create({
      postTitle,
      postContent,
      creatorId,
      excludeLecturers,
      excludeStudents,
      excludeHOD
    });

    customResponse.successResponse(res, 'Post created successfully', 201, { post: newPost });
  } catch (error) {
    customResponse.errorResponse(res, `Failed to create post: ${error}`, 500, {});
  }
};

/*
This endpoint edits a post.
Only the creator of the post can edit it.
*/
export const editPost = async (req: Request, res: Response): Promise<void> => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, {});
      return;
    }

    const token = authHeader.split(' ')[1];
    let userId: string;

    try {
      const secret = JWT_SECRET;
      if (!secret) {
        customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
        return;
      }
      const decoded = jwt.verify(token, secret) as { id: string };
      userId = decoded.id;
    } catch (err) {
      customResponse.errorResponse(res, 'Invalid or expired token', 401, {});
      return;
    }

    const { id } = req.params;
    const { postTitle, postContent, excludeHOD, excludeLecturers, excludeStudents } = req.body;

    try {
      const post = await Post.findByPk(id);
      if (!post) {
        customResponse.errorResponse(res, 'Post not found', 404, {});
        return;
      }

      if (post.creatorId !== userId) {
        customResponse.errorResponse(res, 'You are not authorized to edit this post', 403, {});
        return;
      }

      if (postTitle !== undefined) post.postTitle = postTitle;
      if (postContent !== undefined) post.postContent = postContent;
      if (excludeHOD !== undefined) post.excludeHOD = excludeHOD;
      if (excludeLecturers !== undefined) post.excludeLecturers = excludeLecturers;
      if (excludeStudents !== undefined) post.excludeStudents = excludeStudents;

      await post.save();

      customResponse.successResponse(res, 'Post updated successfully', 200, { post });
    } catch (error) {
      customResponse.errorResponse(res, `Failed to update post: ${error}`, 500, {});
    }
};

/*
This endpoint deletes a post.
Only the creator of the post can delete it.
*/
export const deletePost = async (req: Request, res: Response): Promise<void> => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, {});
    return;
  }

  const token = authHeader.split(' ')[1];
  let userId: string;

  try {
    const secret = JWT_SECRET;
    if (!secret) {
      customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
      return;
    }
    const decoded = jwt.verify(token, secret) as { id: string };
    userId = decoded.id;
  } catch (err) {
    customResponse.errorResponse(res, 'Invalid or expired token', 401, {});
    return;
  }

  const { id } = req.params;

  try {
    const post = await Post.findByPk(id);
    if (!post) {
      customResponse.errorResponse(res, 'Post not found', 404, {});
      return;
    }

    if (post.creatorId !== userId) {
      customResponse.errorResponse(res, 'You are not authorized to delete this post', 403, {});
      return;
    }

    await post.destroy();

    customResponse.successResponse(res, 'Post deleted successfully', 200, {});
  } catch (error) {
    customResponse.errorResponse(res, `Failed to delete post: ${error}`, 500, {});
  }
};

/*
 * This endpoint fetches all posts based on the role from the access token.
 * - If excludeLecturers is true, those posts are hidden from lecturers.
 * - If excludeStudents is true, those posts are hidden from students.
 */
export const getPostsForTimeline = async (req: Request, res: Response): Promise<void> => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    customResponse.errorResponse(res, 'Missing token', 401, {});
    return;
  }

  const token = authHeader.split(' ')[1];
  let user: User | null = null;
  try {
    const secret = JWT_SECRET;
    if (!secret) {
      customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
      return;
    }
    const decoded = jwt.verify(token, secret) as { id: string };
    user = await User.findByPk(decoded.id);
    if (!user) throw new Error();
  } catch {
    customResponse.errorResponse(res, 'Invalid token', 401, {});
    return;
  }

  const page = parseInt(req.query.page as string) || 1;
  const limit = parseInt(req.query.limit as string) || 10;
  const offset = (page - 1) * limit;

  const whereClause: any = {};
  if (user.isHOD) whereClause.excludeHOD = { [Op.ne]: true };
  if (user.isLecturer) whereClause.excludeLecturers = { [Op.ne]: true };
  if (user.isStudent) whereClause.excludeStudents = { [Op.ne]: true };

  try {
    const posts = await Post.findAndCountAll({
      where: whereClause,
      order: [['createdAt', 'DESC']],
      limit,
      offset,
    });

    customResponse.successResponse(res, 'Posts fetched successfully', 200, {
      posts: posts.rows,
      total: posts.count,
      page,
      pages: Math.ceil(posts.count / limit),
    });
  } catch (error) {
    customResponse.errorResponse(res, `Failed to fetch posts: ${error}`, 500, {});
  }
};

/*
 * This endpoint fetches all posts created by the user whose id is in the access token.
 */
export const getUserPosts = async (req: Request, res: Response): Promise<void> => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    customResponse.errorResponse(res, 'Authorization header is missing or invalid', 401, {});
    return;
  }

  const token = authHeader.split(' ')[1];
  let id: string;

  try {
    const secret = JWT_SECRET;
    if (!secret) {
      customResponse.errorResponse(res, 'JWT secret is not configured', 500, {});
      return;
    }
    const decoded = jwt.verify(token, secret) as { id: string };
    id = decoded.id;
  } catch (err) {
    customResponse.errorResponse(res, 'Invalid or expired token', 401, {});
    return;
  }

  try {
    const posts = await Post.findAll({
      where: { creatorId: id },
      order: [['createdAt', 'DESC']],
    });

    customResponse.successResponse(res, 'User posts fetched successfully', 200, { posts });
  } catch (error) {
    customResponse.errorResponse(res, `Failed to fetch user posts: ${error}`, 500, {});
  }
};

/*
 * This endpoint fetches all posts from a user by email or userId.
 * Query params: ?email=... or ?userId=...
 */
export const getPostsByUser = async (req: Request, res: Response): Promise<void> => {
  const { email, userId } = req.body;

  if (!email && !userId) {
    customResponse.errorResponse(res, 'Provide either email or userId', 400, {});
    return;
  }

  let user: User | null = null;
  try {
    if (email) {
      user = await User.findOne({ where: { email } });
    } else if (userId) {
      user = await User.findByPk(userId as string);
    }

    if (!user) {
      customResponse.errorResponse(res, 'User not found', 404, {});
      return;
    }

    const posts = await Post.findAll({
      where: { creatorId: user.id },
      order: [['createdAt', 'DESC']],
    });

    customResponse.successResponse(res, 'Posts fetched successfully', 200, { posts });
  } catch (error) {
    customResponse.errorResponse(res, `Failed to fetch posts: ${error}`, 500, {});
  }
};