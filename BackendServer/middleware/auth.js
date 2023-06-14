const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const conn = require('../services/db');
const { addToken, getToken, blacklistToken } = require('../services/token');

dotenv.config();

const userTable = 'contact';
const userQuery = `SELECT is_active, is_locked FROM ${userTable} WHERE contact_id = ?`;

async function auth(req, res, next) {
	try {
		const authHeader = req.headers.authorization;
		const token = authHeader && authHeader.split(' ')[1];

		if (token == null) throw 'No authorization header';
		
		const decodedToken = await jwt.verify(token, process.env.TOKEN_SECRET);
		const user_id = decodedToken.user_id;

		const result = await conn.query(userQuery, [user_id]);

		if (result && result.length === 1) {
			if (result[0].is_locked) {
				res.status(403).json({message: "Your account is locked"});
			} 

			if (!result[0].is_active) {
				res.status(403).json({message: "Your account is inactive"});
			}

			next();
		} else {
			throw 'User doest not exist!';
		}

	} catch (err) {
		if (err.name === 'TokenExpiredError') {
			res.status(401).json({
				error: 'Token expired'
			});
		} else {
			console.log(err);
			res.status(400).json({
				error: err
			});
			
		}
	}
};

module.exports = {
	auth,
}
