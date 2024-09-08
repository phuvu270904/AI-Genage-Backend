import express from 'express';
import * as dotenv from 'dotenv';

dotenv.config();

const router = express.Router();

router.route('/').get((req, res) => {
    res.send("Hello from AI-Genage");
})

router.route('/').post(async (req, res) => {
    try {
        const response = await fetch(
            "https://api-inference.huggingface.co/models/ZB-Tech/Text-to-Image",
            {
                headers: {
                    "Authorization": `Bearer ${process.env.HUGGINGFACE_API_KEY}`,
                    "Content-Type": "application/json",
                },
                method: "POST",
                body: JSON.stringify(req.body),
            }
        );
        
        const arrayBuffer = await response.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        const base64Photo = buffer.toString('base64');
        
        res.status(200).send({photo: `data:image/jpeg;base64,${base64Photo}`});

    } catch (error) {
        console.log(error);
        res.status(500).send(error?.response?.data?.error?.message || 'Internal Server Error');
    }
});

export default router;