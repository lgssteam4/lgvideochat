const { body } = require('express-validator');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

const conn = require('./db');
const utils = require('../utils');
const config = require('../config');

dotenv.config();

const userTable = "contact";

async function getAllUsers(res, page = 1) {
  const offset = utils.getOffset(page, config.listPerPage);
  const rows = await conn.query(
    `SELECT contact_id, email, last_name, first_name, ip_address
    FROM ${userTable} LIMIT ${offset}, ${config.listPerPage}`
  );
  const data = utils.emptyOrRows(rows);
  const meta = {page};

  return res.status(200).json({
    data,
    meta
  });
}

async function getUser(res, id) {
	const row = await conn.query(
		`SELECT contact_id, email, last_name, first_name, ip_address, password
		FROM ${userTable} WHERE contact_id = ?`,
		[id]
	);

	const data = utils.emptyOrRows(row);

	return req.status(200).json({
		data,
	});
}

async function signup(res, user) {
	let hashedPassword = null;
	let message = null;
	let statusCode = null;

	await bcrypt.hash(user.password, 6).then(hash => {
		hashedPassword = hash;
	}).catch(err => {
		message = err.message;
		statusCode = 400;
	});

	if (message !== null) return {message, statusCode};

	const result = await conn.query(
		`INSERT INTO ${userTable}
		(email, first_name, last_name, password, ip_address)
		VALUES
		(?, ?, ?, ?, ?)`,
		[user.email, user.first_name, user.last_name, hashedPassword, user.ip_address]
	);

	if (result.affectedRows) {
		const user_db = await conn.query(
			`SELECT contact_id, email, first_name from ${userTable}
			WHERE email = ?`,
			[user.email]
		);

		const token = utils.generateActivationToken(user_db[0].contact_id);

		message = 'User created successfully. Please check your email to activate your account!';
		statusCode = 200;

		// Generate token
		const activationURL = `${process.env.BASE_URL}/user/verify/${user_db[0].contact_id}/${token}`;
		utils.sendActivationEmail({src: process.env.MAIL_USER, dst: user_db[0].email, name: user_db[0].first_name, activationURL: activationURL});

	} else {
		message = 'Error creating user!';
		statusCode = 400;
	}

	return res.status(statusCode).json({message});
}

async function updateUser(res, id, user){
	let message = null;

	const result = await conn.query(
		`UPDATE ${userTable}
		SET email=?, first_name=?, last_name=?, ip_address=?
		WHERE contact_id=?`,
		[user.email, user.first_name, user.last_name, user.ip_address, user.contact_id]
	);


	if (result.affectedRows) {
		message = 'User updated successfully';
		statusCode = 200;
	} else {
		message = 'Error in updating user';
		statusCode = 400;
	}

	return req.status(statusCode).json({message});
}

async function deactivateUser(res, id) {
	let message = null;
	let statusCode = null;

	const query = `UPDATE ${userTable} 
				   SET is_active = false
				   WHERE contact_id = ?`
	const result = await conn.query(query, [id]);

	if (result.affectedRows) {
		message = 'User deactivated successfully';
		statusCode = 200;
	} else {
		message = 'Failed to deactivate user!';
		statusCode = 400;
	}

	return req.status(statusCode).json({message});
}

async function login(res, data) {
	let message = null;
	let statusCode = null;

	const query = `SELECT * FROM ${userTable} WHERE email = ?`;
	
	const result = await conn.query(query, [data.email]);
	if (result && result.length === 1) {
		// Check password first
		const isCorrect = bcrypt.compareSync(data.password, result[0].password);
		if (isCorrect === true) {
			// Password is correct
			if (result[0].is_active === 1) {
				// Password is correct and account is active
				message = "Login successful"
				statusCode = 200;

				console.log("correct password");
				const token = utils.generateAccessToken(result[0].contact_id);
				return res.status(statusCode).json({message, token});
			} else {
				// Password is correct but account is not activated yet.
				message = "Account is not activated"
				statusCode = 403;
			}
		} else {
			// Wrong password
			message = "Invalid credentials";
			statusCode = 401;
		}
	} else {
		message = "Invalid credentials";
		statusCode = 401;
	}

	return res.status(statusCode).json({message});
}

async function activateUser(res, {user_id, token}) {
}

module.exports = {
	getAllUsers,
	getUser,
	signup,
	updateUser,
	deactivateUser,
	login
}
