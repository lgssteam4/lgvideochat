const redis = require('redis');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

async function createRedisConnection() {
		const client = redis.createClient();
				client.on("connect", (err) => {
				console.log("Client connected to Redis...");
		});
				client.on("ready", (err) => {
				console.log("Redis ready to use");
		});
		client.on("error", (err) => {
		console.error("Redis Client", err);
		});
		client.on("end", () => {
		console.log("Redis disconnected successfully");
		});
		await client.connect();
		return client;
}

const addToken = async(user_id, token, expiredAt) => {
	try {
		const client = await createRedisConnection();
		await client.SET(user_id, token); // Overwrite token if existed
		await client.EXPIREAT(user_id, expiredAt/1000); // sets the token expiration date based on the password expired datetime.
		return true;
	} catch (e) {
		console.error("Token not added to cache")
		console.log(e);
		return false;
    }
};

const getToken = async (userId) => {
    try {
	const client = await createRedisConnection();
        const token = await client.GET(userId); // get the token from the cache and return its value
        return token;
    } catch (e) {
        console.error("Fetching token from cache failed")
    }
};

const blacklistToken = async(token) => {
    try {
				const client = await createRedisConnection();
        const status = await client.SET(token, "invalid"); // sets the value of the JWT to be invalid
        if (status == "nil") console.error("Token does not exist in cache");
        const payload = await jwt.verify(token, "secret-key") // verifies and decode the jwt to get the expiration date
        await client.EXPIREAT(token, +payload.exp); // sets the token expiration date to be removed from the cache
        return;
    } catch(e) {
        console.error("Token not invalidated")
    }
};

module.exports = {
	blacklistToken,
	getToken,
	addToken
}
