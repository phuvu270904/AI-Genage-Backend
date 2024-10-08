import express from 'express';
import * as dotenv from 'dotenv';
import cors from 'cors';
import connectDB from './mongodb/connect.js';
import postRoutes from './routes/postRoutes.js';
import generateRoutes from './routes/generateRoutes.js';
import authRoutes from './routes/authRoutes.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/posts', postRoutes);
app.use('/api/v1/generate', generateRoutes);

app.get('/', async (req, res) => {
    res.send('Hello from AI-Genage');
});

const startServer = async () => {
    try {
        connectDB(process.env.MONGODB_URL);        
        app.listen(8080, () => console.log('Server is running on port 8080'));
    } catch (error) {
        console.log(error);
    }
}

startServer();