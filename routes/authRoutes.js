import express from 'express';
import * as dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import randToken from 'rand-token';

import User from '../mongodb/models/user.js';

dotenv.config();

const router = express.Router();

router.route('/register').post(async (req, res) => {
    const username = req.body.username.toLowerCase();
	const user = await User.findOne({ username });
	if (user) res.status(409).send('User already exists');
	else {
		const hashPassword = bcrypt.hashSync(req.body.password, 10);
		const newUser = {
			username: username,
			password: hashPassword,
		};
		const createUser = await User.create(newUser);
		if (!createUser) {
			return res
				.status(400)
				.send('Error creating user');
		}
		return res.send({
			username
		});
	}
});

router.route('/login').post(async (req, res) => {
    const username = req.body.username.toLowerCase() || 'test';
	const password = req.body.password || '12345';

	const user = await User.findOne({ username });
	if (!user) {
		return res.status(401).send('Username or password is incorrect');
	}

	const isPasswordValid = bcrypt.compareSync(password, user.password);
	if (!isPasswordValid) {
		return res.status(401).send('Password is incorrect');
	}

	const accessTokenLife = process.env.ACCESS_TOKEN_LIFE;
	const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;

	const dataForAccessToken = {
		username: user.username,
	};

    const accessToken = jwt.sign(dataForAccessToken, accessTokenSecret, { expiresIn: accessTokenLife });
	
	if (!accessToken) {
		return res
			.status(401)
			.send('Error creating access token');
	}

	let refreshToken = randToken.generate(16);

	if (!user.refreshToken) {
		await User.updateOne({ username }, { refreshToken });
	} else {
		refreshToken = user.refreshToken;
	}

	return res.json({
		msg: 'Login success',
		accessToken,
		refreshToken,
		username: user.username,
	});
});

router.route('/refresh').post(async (req, res) => {
	const accessTokenFromHeader = req.headers.x_authorization;
	if (!accessTokenFromHeader) {
		return res.status(400).send('Cannot find access token.');
	}

	const refreshTokenFromBody = req.body.refreshToken;
	if (!refreshTokenFromBody) {
		return res.status(400).send('Cannot find refresh token.');
	}

	const accessTokenSecret =
		process.env.ACCESS_TOKEN_SECRET || jwtVariable.accessTokenSecret;
	const accessTokenLife =
		process.env.ACCESS_TOKEN_LIFE || jwtVariable.accessTokenLife;

	const decoded = await jwt.verify(accessTokenFromHeader, accessTokenSecret, { ignoreExpiration: true });

	if (!decoded) {
		return res.status(400).send('Access token is invalid.');
	}

	const username = decoded.username;

	const user = await User.findOne({username});
	if (!user) {
		return res.status(401).send('User not found');
	}

	if (refreshTokenFromBody !== user.refreshToken) {
		return res.status(400).send('Invalid refresh token');
	}

	const dataForAccessToken = {
		username
	};

	const accessToken = jwt.sign(dataForAccessToken, accessTokenSecret, { expiresIn: accessTokenLife });

	if (!accessToken) {
		return res
			.status(400)
			.send('Error creating access token');
	}
	return res.json({
		accessToken,
	});
});

export default router;