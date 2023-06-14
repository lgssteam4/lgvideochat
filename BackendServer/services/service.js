const { body } = require('express-validator');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

const db = require('./db');
const utils = require('../utils');
const config = require('../config');

dotenv.config();

const userTable = "contact";
const authTable = "auth";

async function getAllUsers(res, page = 1) {
  const offset = utils.getOffset(page, config.listPerPage);
  const rows = await db.query(
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
	const row = await db.query(
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

	const passwordExpiredAt = new Date(new Date().setDate(new Date().getDate() + 30));

	const result = await db.query(
		`INSERT INTO ${userTable}
		(email, first_name, last_name, password, ip_address, password_expired_at)
		VALUES
		(?, ?, ?, ?, ?, ?)`,
		[user.email, user.first_name, user.last_name, hashedPassword, user.ip_address, passwordExpiredAt]
	);

	if (result.affectedRows) {
		const user_db = await db.query(
			`SELECT contact_id, email, first_name from ${userTable}
			WHERE email = ?`,
			[user.email]
		);
		
		// Create auth 
		await db.query(
			`INSERT INTO ${authTable}
			(contact_id)
			VALUES
			(?)`,
			[user_db[0].contact_id]
		);

		utils.sendActivationEmail({dst: user_db[0].email, userId: user_db[0].contact_id, name: user_db[0].first_name});

		message = 'User created successfully. Please check your email to activate your account!';
		statusCode = 200;


	} else {
		message = 'Error creating user!';
		statusCode = 400;
	}

	return res.status(statusCode).json({message});
}

async function updateUser(res, id, user){
	let message = null;

	const result = await db.query(
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
	const result = await db.query(query, [id]);

	if (result.affectedRows) {
		message = 'User deactivated successfully';
		statusCode = 200;
	} else {
		message = 'Failed to deactivate user!';
		statusCode = 400;
	}

	return req.status(statusCode).json({message});
}

async function login(res, {email, password}) {
	let message = null;
	let statusCode = null;

	const query = `SELECT * FROM ${userTable} WHERE email = ?`;
	
	const result = await db.query(query, [email]);
	if (result && result.length === 1) {
		if (result[0].is_locked === 1) {
			message = "Your account is locked";
			return res.status(403).json({message});
		}

		// Check password 
		const isCorrect = bcrypt.compareSync(password, result[0].password);
		if (isCorrect === true) {
			// Password is correct
			if (result[0].is_active === 1) {
				// Password is correct and account is active
				message = `OTP sent to ${result[0].email}`;
				statusCode = 200;

				const otp = utils.generateOTP();
				const rc = await storeOTP(result[0].contact_id, otp, process.env.LOGIN_OTP_DURATION_MIN);
				if (rc) {
					const loginToken = utils.generateLoginToken(result[0].contact_id);
					utils.sendOTPEmail({dst: result[0].email, otp: otp});

					return res.status(statusCode).json({message: message, login_token: loginToken});
				} 

				message = "Error generating OTP";
				statusCode = 500
			} else {
				// Password is correct but account is not activated yet.
				message = "Account is not activated"
				statusCode = 403;
			}
		} else {
			// Wrong password, check failed attempts
			const otpQuery = `SELECT failed_attempt FROM auth WHERE contact_id = ?`;
			const otpResult = await db.query(otpQuery, [result[0].contact_id]);

			const failedAttempts = otpResult[0].failed_attempt + 1;
			await db.query(`UPDATE ${authTable} SET failed_attempt = ${failedAttempts} WHERE contact_id = ?`, [result[0].contact_id]);

			message = "Failed to login";
			statusCode = 401;

			// If failed attempts > threshold, lock account
			if (failedAttempts > process.env.FAILED_LOGIN_THRESHOLD) {
				await db.query(`UPDATE ${userTable} SET is_locked = true WHERE contact_id = ?`, [result[0].contact_id]);
				message = "Your account is locked";
				statusCode = 403;
			} else {
				message = "Invalid credentials";
				statusCode = 401;
			}
		}

	} else {
		message = "Invalid credentials";
		statusCode = 401;
	}

	return res.status(statusCode).json({message});
}

async function getAccessToken(res, userId, refreshToken) {
	let message = null;
	try {
		const decodedToken = await jwt.verify(refreshToken, process.env.TOKEN_SECRET);
		const tokenFromRedis = await db.getToken(userId);
		if (decodedToken && decodedToken.user_id === userId && refreshToken === tokenFromRedis) {
			const accessToken = await utils.generateAccessToken(userId);
			return res.status(200).json({refreshToken, accessToken});
		} else {
			message = "Invalid request";
			return res.status(400).json({message});
		}

	} catch (err) {
		if (err.name ===  'TokenExpiredError') {
			message = "Token expired"
			return res.status(403).json({message});
		} else {
			console.log(err);
			message = "Unknown error";
			return res.status(401).json({message});
		}
	} 
}

async function activateUser(res, userId, token) {
	let message = "Failed to activate user";
	let statusCode = 400;
	try {
		const decodedToken = await jwt.verify(token, process.env.TOKEN_SECRET);
		if (decodedToken.user_id === userId) {
			const query = `UPDATE ${userTable} SET is_active = true WHERE contact_id = ?`;
			const result = await db.query(query, [userId]);
			if (result.affectedRows) {
				message = "Activated user successfully";
				statusCode = 200;
			}
		}

		return res.status(statusCode).json({message});

	} catch (err) {
		console.log(err);
		return res.status(statusCode).json(err);
	};
}


async function storeOTP(userId, otp, duration) {
	try {
		const otpExpiredAt = new Date(new Date().setMinutes(new Date().getMinutes() + duration));
		const query = `UPDATE ${authTable} SET otp=?, expired_at=?, otp_used=false WHERE contact_id = ?`;
		const result = await db.query(query, [otp, otpExpiredAt, userId]);

		if (result.affectedRows) return true;

		return false;

	} catch (err) {
		console.log(err);
		return false;
	}
}

async function verifyOTP(res, userId, otp) {
	// Only user with valid login token can enter here
	let response = null;
	const now = new Date();
	const otpQuery = `SELECT 1 FROM auth WHERE contact_id = ? AND otp_used = false AND otp = ? AND expired_at > '${now}'`;
	const otpResult = await db.query(otpQuery, [userId, otp]);

	const userQuery = `SELECT password_expired_at FROM ${userTable} WHERE contact_id = ?`;
	const userResult = await db.query(userQuery, [userId]);

	if (otpResult && otpResult.length === 1) {
		// Set OTP as used
		db.query(`UPDATE ${authTable} SET otp_used = true WHERE contact_id = ?`, [userId]);

		// If password is expired, lock the account
		if (userResult[0].password_expired_at < now) {
			console.log("Password is expired");
			message = "Password is expired. Please reset your password";
			statusCode = 403;
			response = {message, statusCode};
		} else {
			const accessToken = utils.generateAccessToken(userId);
			const refreshToken = utils.generateRefreshToken(userId);
			await db.addToken(userId, refreshToken, userResult[0].password_expired_at);
			await db.query(`UPDATE ${authTable} SET failed_attempt = 0 WHERE contact_id = ?`, [userId]);

			
			message = "Successfully login";
			statusCode = 200;
			response = {message: message, access_token: accessToken, refresh_token: refreshToken};
		}

		return res.status(statusCode).json(response);

	} else {
		// Failed to login
		const otpQuery = `SELECT failed_attempt FROM auth WHERE contact_id = ?`;
		const otpResult = await db.query(otpQuery, [userId]);

		const failedAttempts = otpResult[0].failed_attempt + 1;
		await db.query(`UPDATE ${authTable} SET failed_attempt = ${failedAttempts} WHERE contact_id = ?`, [userId]);

		message = "Failed to login";
		statusCode = 401;

		// If failed attempts > threshold, lock account
		if (failedAttempts > process.env.FAILED_LOGIN_THRESHOLD) {
			await db.query(`UPDATE ${userTable} SET is_locked = true WHERE contact_id = ?`, [userId]);
			message = "Your account is locked";
			statusCode = 403;
		}

		res.status(statusCode).json({message});
	}
}

async function requestUpdateEmail(res, {id, password, newEmail}) {
	let message = null;
	let statusCode = null;

	const query = `SELECT contact_id, email, password, first_name FROM ${userTable} WHERE contact_id = ? AND is_active = true AND is_locked = false`;
	const result = await db.query(query, [id]);

	if (!result || result.length !== 1) {
		return res.status(400).json("User not found");
	}

	const isCorrect = bcrypt.compareSync(password, result[0].password);
	if (isCorrect) {
		if (result[0].email !== newEmail) {
			const confirmationCode = utils.generateOTP();
			storeOTP(result[0].contact_id, confirmationCode, process.env.UPDATE_EMAIL_OTP_DURATION_MIN);
			utils.sendEmailUpdateConfirmation({dst: newEmail, name: result[0].first_name, confirmationCode: confirmationCode});
			message = "Confirmation code is sent to the new email"
			statusCode = 200

		} else {
			message = "Email is not changed";
			statusCode = 400;
		}
	} else {
		message = "Invalid password"
		statusCode = 401
	}

	return res.status(statusCode).json({message});

}

async function requestResetPassword(res, email) {
	// Only user with valid login token can enter here
	let response = null;
	let message = null;
	const userQuery = `SELECT * FROM ${userTable} WHERE email = ? AND is_active = true`;
	const userResult = await db.query(userQuery, [email]);

	if (userResult && userResult.length === 1) {
		const resetToken = utils.generateResetPasswordToken(userResult[0].contact_id);

		message = "Please check your email to get the confirmation code";
		statusCode = 200;

		const confirmationCode = utils.generateOTP();
		storeOTP(userResult[0].contact_id, confirmationCode, process.env.RESET_PASSWORD_OTP_DURATION_MIN);
		utils.sendResetPasswordEmail({dst: email, name: userResult[0].first_name, confirmation_code: confirmationCode});

		response = {message, reset_token: resetToken};
	} else {
		message = "Email does not exist";
		statusCode = 400;

		response = {message}
	}

	return res.status(statusCode).json(response);
}

async function resetPassword(res, {userId, password, otp}) {
	// Only user with valid login token can enter here
	const now = new Date();
	let response = null;
	let message = null;

	const otpQuery = `SELECT 1 FROM auth WHERE contact_id = ? AND otp_used = false AND otp = ? AND expired_at > '${now}'`;
	const otpResult = await db.query(otpQuery, [userId, otp]);

	if (!otpResult || otpResult.length === 1) {
		return res.status(400).json("Invalid credentials");	
	}

	await bcrypt.hash(password, 6).then(hash => {
		hashedPassword = hash;
	}).catch(err => {
		message = err.message;
		statusCode = 400;
	});

	if (message !== null) return {message, statusCode};

	const passwordExpiredAt = new Date(new Date().setDate(new Date().getDate() + 30));

	const query = `UPDATE ${userTable} SET password = ?, password_expired_at = ?, is_locked = false WHERE contact_id = ?`;
	const result = await db.query(query, [hashedPassword, passwordExpiredAt, userId]);

	if (result.affectedRows) {
		db.query(`UPDATE ${authTable} SET failed_attempt = 0 WHERE contact_id = ?`, [userId]);
		message = "Successfully changed password";
		statusCode = 200;
		
	} else {
		message = "Failed to change password";
		statusCode = 400;
	}

	return res.status(statusCode).json({message});
}

module.exports = {
	signup,
	activateUser,
	login,
	getAllUsers,
	getUser,
	updateUser,
	requestUpdateEmail,
	deactivateUser,
	getAccessToken,
	verifyOTP,
	requestResetPassword,
	resetPassword
}
