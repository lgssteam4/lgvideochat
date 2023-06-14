const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');
const dotenv = require("dotenv");

dotenv.config();

const transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASSWORD
    }
});

function getOffset(currentPage = 1, listPerPage) {
  return (currentPage - 1) * [listPerPage];
}

function emptyOrRows(rows) {
  if (!rows) {
    return [];
  }
  return rows;
}

function validatePasswordComplexity(password) {
	/* Length between 8 and 32 characters.
	 * One or more uppercase letters.
	 * One or more lowercase letters.
	 * One or more numbers.
	 * One or more special characters (ASCII punctuation or space characters).
	*/
	const minMaxLength = /^[\s\S]{8,32}$/,
        upper = /[A-Z]/,
        lower = /[a-z]/,
        number = /[0-9]/,
        special = /[!#$%&()*+,\-./:;<=>?@[\\\]^_`{|}~]/;

    if (minMaxLength.test(password) &&
        upper.test(password) &&
        lower.test(password) &&
        number.test(password) &&
        special.test(password)
    ) {
        return true;
    }

    return false;
}

function validateIpAddress(ip) {
	const reg = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

	if (reg.test(ip)) return true;
	
	return false;
}

function comparePassword(plaintextPassword, hash) {
   bcrypt.compare(plaintextPassword, hash)
       .then(result => {
		   console.log(result);
           return result
       })
       .catch(err => {
           console.log(err);
       })
}

function generateAccessToken(user_id) {
	return jwt.sign({user_id}, process.env.TOKEN_SECRET, { expiresIn: `${process.env.ACCESS_TOKEN_EXPIRED_DURATION}h` });
}

function generateRefreshToken(user_id) {
	return jwt.sign({user_id}, process.env.TOKEN_SECRET, { expiresIn: `${process.env.REFRESH_TOKEN_EXPIRED_DURATION}h` });
}

function generateActivationToken(user_id) {
	return jwt.sign({user_id}, process.env.TOKEN_SECRET, { expiresIn: `${process.env.ACTIVATION_TOKEN_EXPIRED_DURATION}h` });
}

function generateLoginToken(user_id) {
	return jwt.sign({user_id}, process.env.TOKEN_SECRET, { expiresIn: `${process.env.LOGIN_OTP_DURATION_MIN} min` });
}

function generateResetPasswordToken(user_id) {
	return jwt.sign({user_id}, process.env.TOKEN_SECRET, { expiresIn: `${process.env.RESET_TOKEN_DURATION_HOUR}h` });
}

function sendActivationEmail({dst, userId, name}) {
	const token = generateActivationToken(userId);
	const activationURL = `${process.env.BASE_URL}/api/user/${userId}/verify/${token}`;

	transporter.sendMail({
		from: process.env.MAIL_USER,
		to: dst,
		subject: "LGE Video Chat - Account Activation",
		html: `<h1>Email Confirmation</h1>
			<h2>Hello ${name}</h2>
			<p>Thank you for registration. Please confirm your email by clicking on the following link</p>
			<a href=${activationURL}> Click here</a>
			</div>`,
	}).catch((err) => {
		console.log(err);
	});
}

function sendResetPasswordEmail({dst, name, confirmation_code}) {
	transporter.sendMail({
		from: process.env.MAIL_USER,
		to: dst,
		subject: "LGE Video Chat - Reset Password",
		html: `<h1>Email Confirmation</h1>
			<h2>Hello ${name}</h2>
			<p>You recently requested to reset the password for your LG Chat account. If you did not request a password reset, please ignore this email or reply to let us know.</p>
			<p>Here is your confirmation code: <b>${confirmation_code}</b></p>
			</div>`,
	}).catch((err) => {
		console.log(err);
	});
}

function sendOTPEmail({dst, otp}) {
	transporter.sendMail({
		from: process.env.MAIL_USER,
		to: dst,
		subject: "LGE Video Chat - OTP",
		html: `<h1>Two-Factor Authorization</h1>
			<p>Your OTP will be expired in 1 minute. If you did not request the OTP, please consider changing your password.</p>
			<p>OTP: <b>${otp}</b></p>
			</div>`,
	}).catch((err) => {
		console.log(err);
	});
}

function generateOTP() {
	return Math.floor(100000 + Math.random() * 900000);
}

function sendEmailUpdateConfirmation({dst, name, confirmationCode}) {
	console.log(name);
	transporter.sendMail({
		from: process.env.MAIL_USER,
		to: dst,
		subject: "LGE Video Chat - Email Update Confirmation",
		html: `<h1>Email Update</h1>
			<h2>Dear ${name}</h2>
			<p>You recently requested to update the email of your LG Chat account. If you did not request to change your email, please contact us immediately to report any unauthorized access to your account.</p>
			<p>Confirmation code: ${confirmationCode}</p>
			</div>`,
	}).catch((err) => {
		console.log(err);
	});
}


module.exports = {
	getOffset,
	emptyOrRows,
	validatePasswordComplexity,
	validateIpAddress,
	comparePassword,
	generateAccessToken,
	generateRefreshToken,
	generateActivationToken,
	generateLoginToken,
	generateResetPasswordToken,
	sendActivationEmail,
	sendResetPasswordEmail,
	sendEmailUpdateConfirmation,
	generateOTP,
	sendOTPEmail
}
