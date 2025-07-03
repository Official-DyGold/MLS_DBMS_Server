import express from 'express'
import { 
    createPost,
    editPost,
    deletePost,
    getPostsForTimeline,
    getUserPosts,
    getPostsByUser,
} from '../controllers/post.control';
import authMiddleware from '../middlewares/auth.middleware'

const router = express.Router();

router.post('/create-post', authMiddleware, createPost)
router.put('/edit-post/:id', authMiddleware, editPost)
router.delete('/delete-post/:id', authMiddleware, deletePost)
router.get('/user-timeline', authMiddleware, getPostsForTimeline)
router.get('/get-my-posts', authMiddleware, getUserPosts)
router.get('/get-user-posts-by-id-or-email', authMiddleware, getUserPosts)

/**
 * @swagger
 * /api/posts/create-post:
 *   post:
 *     summary: Create a new post
 *     tags:
 *       - Posts
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - postTitle
 *               - postContent
 *             properties:
 *               postTitle:
 *                 type: string
 *                 example: "Important Notice"
 *               postContent:
 *                 type: string
 *                 example: "Classes will resume on Monday."
 *               excludeLecturers:
 *                 type: boolean
 *                 example: false
 *               excludeStudents:
 *                 type: boolean
 *                 example: true
 *     responses:
 *       201:
 *         description: Post created successfully
 *       400:
 *         description: Missing title or content
 *       401:
 *         description: Unauthorized or invalid token
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/posts/edit-post/{id}:
 *   put:
 *     summary: Edit a post by its ID
 *     tags:
 *       - Posts
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the post to edit
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               postTitle:
 *                 type: string
 *               postContent:
 *                 type: string
 *               excludeLecturers:
 *                 type: boolean
 *               excludeStudents:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Post updated successfully
 *       403:
 *         description: Not authorized to edit this post
 *       404:
 *         description: Post not found
 *       401:
 *         description: Invalid token
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/posts/delete-post/{id}:
 *   delete:
 *     summary: Delete a post by its ID
 *     tags:
 *       - Posts
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID of the post to delete
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Post deleted successfully
 *       403:
 *         description: Not authorized to delete this post
 *       404:
 *         description: Post not found
 *       401:
 *         description: Invalid or missing token
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/posts/user-timeline:
 *   get:
 *     summary: Fetch posts for user's timeline
 *     description: Returns paginated posts filtered by user role. Posts marked with `excludeLecturers` or `excludeStudents` will not be shown to those roles.
 *     tags:
 *       - Posts
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: page
 *         in: query
 *         required: false
 *         schema:
 *           type: integer
 *         description: "Page number (default: 1)"
 *       - name: limit
 *         in: query
 *         required: false
 *         schema:
 *           type: integer
 *         description: "Number of posts per page (default: 10)"
 *     responses:
 *       200:
 *         description: Posts fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 posts:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Post'
 *                 total:
 *                   type: integer
 *                 page:
 *                   type: integer
 *                 pages:
 *                   type: integer
 *       401:
 *         description: Invalid or missing token
 *       500:
 *         description: Server error
 */

/**
 * @swagger
 * /api/posts/get-my-posts:
 *   get:
 *     summary: Get all posts created by the currently logged-in user
 *     description: Fetches posts created by the user based on the access token provided in the Authorization header.
 *     tags:
 *       - Posts
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Posts retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 posts:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Post'
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       500:
 *         description: Internal server error
 */

/**
 * @swagger
 * /api/posts/get-user-posts-by-id-or-email:
 *   post:
 *     summary: Get posts by user email or userId
 *     description: Returns all posts created by a user identified by either email or userId.
 *     tags:
 *       - Posts
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               userId:
 *                 type: string
 *                 example: 123
 *             oneOf:
 *               - required: [email]
 *               - required: [userId]
 *     responses:
 *       200:
 *         description: Posts retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 posts:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Post'
 *       400:
 *         description: Bad request - email or userId required
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */


export default router 