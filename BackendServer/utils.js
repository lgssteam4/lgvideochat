const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

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
  return jwt.sign(user_id, process.env.TOKEN_SECRET, { expiresIn: process.env.TOKEN_EXPIRED_DURATION });
}


module.exports = {
	getOffset,
	emptyOrRows,
	validatePasswordComplexity,
	validateIpAddress,
	comparePassword,
	generateAccessToken
}
