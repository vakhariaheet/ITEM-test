const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

require('dotenv').config();
const userSchema = new Schema({
	username: { type: String, unique: true },
	password: String,
	email: String,
	loginHistory: [
		{
			dateTime: Date,
			userAgent: String,
		},
	],
});

let User; // to be defined on new connection (see initialize)

module.exports.initialize = () => {
	return new Promise((resolve, reject) => {
		let db = mongoose.createConnection(process.env.MONGODB_URI);
		db.on('error', (err) => {
			reject(err); // reject the promise with the provided error
		});
		db.once('open', () => {
			User = db.model('users', userSchema);
			resolve();
		});
	});
};

const hashPassword = (plainTextPassword) => {
	return bcrypt.hashSync(plainTextPassword, 10);
};
const validatePassword = (plainTextPassword, hashedPassword) => {
	return bcrypt.compareSync(plainTextPassword, hashedPassword);
};

const registerUser = (userData) => {
	return new Promise((resolve, reject) => {
		if (userData.password != userData.password2) {
			reject('Passwords do not match');
		} else {
			// Step 1: create a new user object
			let newUser = new User(userData);
			// Step 2: Hash the password
			newUser.password = hashPassword(userData.password);
		
			// Step 3: save the user object
			newUser.save().then((user) => {
				resolve(user);
			})
				.catch((err) => { 
					if (err.code == 11000) {
						reject('User Name already taken');
					} else {
						reject('There was an error creating the user: ' + err);
					}
				});
		}
	});
};

const checkUser = (userData) => {
	return new Promise((resolve, reject) => {
		User.find({ username: userData.username })
			.exec()
			.then((users) => {
				if (users.length === 0) {
					return reject(`${userData.username} not found`);
				}
				if (!validatePassword(userData.password, users[0].password)) {
					return reject(`${userData.username} not found`);
				}

				users[0].loginHistory.push({
					dateTime: new Date().toString(),
					userAgent: userData.userAgent,
				});
				User?.updateOne(
					{ username: users[0].username },
					{ $set: { loginHistory: users[0].loginHistory } },
					{ multi: false },
				)
					.exec()
					.then(() => {
						resolve(users[0]);
					})
					.catch((err) => {
						reject('There was an error verifying the user: ' + err);
                    });
                
			});
	});
};

module.exports.registerUser = registerUser;
module.exports.checkUser = checkUser;


