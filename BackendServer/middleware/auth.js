const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const conn = require('../services/db');


dotenv.config();

const userTable = 'contacts';

async function auth(req, res, next) {
	try {
		const authHeader = req.headers.authorization;
		const token = authHeader && authHeader.split(' ')[1];

		if (token == null) throw 'No authorization header';

		const decodedToken = await jwt.verify(token, process.env.TOKEN_SECRET);
		const contactId = decodedToken.contact_id;
		console.log(contactId);

		const query = `SELECT 1 FROM ${userTable} WHERE contact_id = ? `
		const result = await conn.query(query, [contactId]);

		if (result && result.length === 1) {
			next();
		} else {
			throw 'User doest not exist!';
		}


	} catch (err) {
		console.log(err);
		res.status(401).json({
			error: 'Invalid request!'
		});
	}
};

function getAuth(req, res, next) {
	try {
		const token = req.headers.authorization.split(' ')[1];
		const decodedToken = jwt.verify(token, SECRET);
		const userId = decodedToken.userId;

		if (req.param.user_id && req.body.userId !== userId) {
			throw 'Invalid user ID';
		} else {
			const query = `SELECT 1 FROM ${userTable} WHERE contact_id = ?`
			const result = conn.query(query, [userId]);
			if (result && result.length === 1) {
				next();
			} else {
				throw 'Invalid user ID';
			}

			next();
		}
	} catch {
		res.status(401).json({
			error: new Error('Invalid request!')
		});
	}
};

function postAuth(req, res, next) {
	try {
		const token = req.headers.authorization.split(' ')[1];
		const decodedToken = jwt.verify(token, SECRET);
		const userId = decodedToken.userId;

		if (req.body.user_id && req.body.userId !== userId) {
			throw 'Invalid user ID';
		} else {
			next();
		}
	} catch {
		res.status(401).json({
			error: new Error('Invalid request!')
		});
	}
};

module.exports = {
	auth,
	getAuth,
	postAuth
}
