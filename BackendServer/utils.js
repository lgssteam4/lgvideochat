const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');
const dotenv = require("dotenv");

dotenv.config();

const transport = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASSWORD,
  },
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
	return jwt.sign({user_id}, process.env.TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRED_DURATION });
}

function generateActivationToken(user_id) {
	console.log(process.env.ACTIVATION_TOKEN_EXPIRED_DURATION);
	return jwt.sign({user_id}, process.env.TOKEN_SECRET, { expiresIn: process.env.ACTIVATION_TOKEN_EXPIRED_DURATION });
}

function sendActivationEmail({src, dst, name, activationURL}) {
	transport.sendMail({
		from: src,
		to: dst,
		subject: "LGE Video Chat - Account Activation",
		html: `<h1>Email Confirmation</h1>
			<h2>Hello ${name}</h2>
			<p>Thank you for registration. Please confirm your email by clicking on the following link</p>
			<a href=${activationURL}> Click here</a>
			</div>`,
	}).catch(err => console.log(err));
}


module.exports = {
	getOffset,
	emptyOrRows,
	validatePasswordComplexity,
	validateIpAddress,
	comparePassword,
	generateAccessToken,
	generateActivationToken,
	sendActivationEmail
}
