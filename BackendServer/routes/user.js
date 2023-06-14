const express = require('express');
const { check, validationResult } = require('express-validator');
const service = require('../services/service');
const utils = require('../utils');
const jwt = require('jsonwebtoken');
const { auth } = require('../middleware/auth');

const router = express.Router();

/* GET users. 
 * example: curl http://localhost:3000/users?page=5
 * */
router.get('/users', auth, async function(req, res, next) {
	try {
		await service.getAllUsers(res, req.query.page);
	} catch (err) {
		console.error(`Error while getting users`, err.message);
		next(err);
	}
});

// Get information of 1 user, a user can not get information of other users -> need to validate token and user id
router.get('/user/:id', auth, async function(req, res, next) {
	try {
		await service.getUser(res, req.params.id);
	} catch (err) {
		console.error(`Error while getting users`, err.message);
		next(err);
	}
});

router.post('/user/signup', 
			[
			check("email").not().isEmpty().withMessage("Email is required").bail().isEmail().normalizeEmail().withMessage("Invalid email"),
			check("first_name").not().isEmpty(),
			check("last_name").not().isEmpty(),
			check('confirm_password', 'Passwords do not match').custom((value, {req}) => (value === req.body.password)),
			check("password").not().isEmpty().custom((value, {req}) => (utils.validatePasswordComplexity(value))).withMessage("Password complexity does not meet requirements!"),
			check('ip_address', 'Invalid IP address').not().isEmpty().custom((value, {req}) => (utils.validateIpAddress(value))),
			], async function(req, res, next) {

	const errors = validationResult(req);

	if (!errors.isEmpty()) {
		return res.status(422).jsonp(errors.array());
	}

	try {
		await service.signup(res, req.body);
	} catch (err) {
		console.error(`Error while getting users`, err.message);
		next(err);
	}
});

router.post('/user/deactivate', auth, async function(req, res, next) {
	try {
		await service.deactivateUser(req.body.user_id);
	} catch (err) {
		console.error(`Error while getting users`, err.message);
		next(err);
	}
});

router.post('/auth/login', [
			check("email", "Invalid email").not().isEmpty().isEmail().normalizeEmail(),
			check("password").not().isEmpty()
			],
			async function(req, res, next) {

	const errors = validationResult(req);

	if (!errors.isEmpty()) {
		return res.status(422).jsonp(errors.array());
	}

	try {
		await service.login(res, req.body);
	} catch (err) {
		console.error(`Error login`, err.message);
		next(err);
	}

});

router.get('/user/:id/verify/:token', async function(req, res, next) {
	try {
		await service.activateUser(res, req.params.id, req.params.token);
	} catch (err) {
		console.error(`Error while activating user`, err.message);
		next(err);
	}
});

// router.post('/user/reset-password', [check]

router.post('/auth/:id/refresh-token', [check("refresh_token").not().isEmpty()], async function(req, res, next) {
	const errors = validationResult(req);

	if (!errors.isEmpty()) {
		return res.status(422).jsonp(errors.array());
	}

	try {
		await service.getAccessToken(res, req.params.id, req.body.refresh_token);
	} catch (err) {
		console.error(`Error while getting access token`, err.message);
		next(err);
	}
});

router.get('/auth/request-otp', async function(req, res, next) {
	const errors = validationResult(req);

	if (!errors.isEmpty()) {
		return res.status(422).jsonp(errors.array());
	}

	try {
		await service.requestOTP(res, userId);
	} catch (err) {
		console.error(`Error while requesting OTP`, err.message);
		next(err);
	}
});

router.post('/auth/verify-otp', [
		check("otp").not().isEmpty().isLength({min: 6, max: 6}).isInt().withMessage("OTP must be 6-digits number"),
		check("login_token").not().isEmpty().withMessage("Login token is required"),
		],
		async function(req, res, next) {

	const errors = validationResult(req);

	if (!errors.isEmpty()) {
		return res.status(422).jsonp(errors.array());
	}

	try {
		const decodedToken = await jwt.verify(req.body.login_token, process.env.TOKEN_SECRET);
		await service.verifyOTP(res, decodedToken.user_id, req.body.otp);

	} catch (err) {
		if (err.name === "TokenExpiredError") {
			return res.status(403).json({message: "Token expired"});

		} else {
			console.error(`Error while verifying OTP`, err.message);
			next(err);
		}
	}
});

router.post('/auth/request-reset-password', [
		check("email").not().isEmpty().isEmail().normalizeEmail(),
		],
		async function(req, res, next) {

	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(422).jsonp(errors.array());
	}

	try {
		await service.requestResetPassword(res, req.body.email);
	} catch (err) {
		console.error(`Error while updating email`, err.message);
		next(err);
	}

});

router.post('/auth/reset-password', [
		check("confirmation_code").not().isEmpty(),
		check("reset_token").not().isEmpty(),
		check("new_password").not().isEmpty().custom((value, {req}) => (utils.validatePasswordComplexity(value))).withMessage("Password complexity does not meet requirements!"),
		check('confirm_password', 'Passwords do not match').custom((value, {req}) => (value === req.body.new_password))
		], async function(req, res, next) {

	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(422).jsonp(errors.array());
	}

	try {
		const decodedToken = await jwt.verify(req.body.reset_token, process.env.TOKEN_SECRET);
		await service.resetPassword(res, {userId: decodedToken.user_id, password: req.body.new_password, otp: req.body.confirmation_code});
	} catch (err) {
		if (err.name === "TokenExpiredError") { 
			res.status(401).json({message: "Token expired"});
		} else {
			console.log(err);
			next(err);
		}
	}
});

router.post('/user/:id/update-email', auth, 
		[
		check("new_email", "Invalid email").not().isEmpty().isEmail(),
		check("password", "Password is required").not().isEmpty()
		], async function(req, res, next) {

	const errors = validationResult(req);

	if (!errors.isEmpty()) {
		return res.status(422).jsonp(errors.array());
	}

	try {
		const authHeader = req.headers.authorization;
                const token = authHeader && authHeader.split(' ')[1];

                const decodedToken = await jwt.verify(token, process.env.TOKEN_SECRET);

		if (decodedToken.user_id === req.params.id) {
			await service.requestUpdateEmail(res,{id: decodedToken.user_id, password: req.body.password, newEmail: req.body.new_email});
		} else {
			return res.status(403).json({message: "Permission denied"});
		}
	} catch (err) {
		console.error(`Error while updating email`, err.message);
		next(err);
	}

});

module.exports = router;
