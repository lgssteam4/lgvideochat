const express = require('express');
const { check, validationResult } = require('express-validator');
const service = require('../services/service');
const utils = require('../utils');
const { auth, getAuth, postAuth } = require('../middleware/auth');

const router = express.Router();

/* GET users. 
 * example: curl http://localhost:3000/users?page=5
 * */
router.get('/', auth, async function(req, res, next) {
	try {
		await service.getAllUsers(res, req.query.page);
	} catch (err) {
		console.error(`Error while getting users`, err.message);
		next(err);
	}
});

// Get information of 1 user, a user can not get information of other users -> need to validate token and user id
router.get('/:id', getAuth, async function(req, res, next) {
	try {
		await service.getUser(res, req.params.id);
	} catch (err) {
		console.error(`Error while getting users`, err.message);
		next(err);
	}
});

router.post('/signup', 
			[
			check("email", "Invalid email").not().isEmpty().isEmail().normalizeEmail(),
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
		await service.createUser(res, req.body);
	} catch (err) {
		console.error(`Error while getting users`, err.message);
		next(err);
	}
});

router.post('/deactivate', postAuth, async function(req, res, next) {
	try {
		await service.deactivateUser(req.body.user_id);
	} catch (err) {
		console.error(`Error while getting users`, err.message);
		next(err);
	}
});

router.post('/login', [
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

module.exports = router;
