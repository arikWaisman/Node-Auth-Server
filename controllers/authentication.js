const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(userModel) {

	const timestamp = new Date().getTime();
	return jwt.encode({ sub: userModel.id, iat: timestamp }, config.secret);

}

exports.signin = function(req, res, next){
	//User has already had their email and password auth'd
	//we just need to give them a token

	//the user is attacherd to the req in the localStrategy in passport.js in the retun done() call
	res.send({ token: tokenForUser(req.user) })

}

exports.signup = function(req, res, next){
	
	const email = req.body.email;
	const password = req.body.password;

	//if either of these are empty lets return early
	if( !email || !password ){
		return res.status(422).send({error: 'You must provide an email and password'});
	}

	//See if a user with the given email exists
	User.findOne( { email: email}, function(err, existingUser){

		if(err) {
			return next(err);		
		}

		//If a user with email does NOT exist, create and save user record
		if(existingUser){
			return res.status(422).send({error: 'Email is in use'});
		}

		//If a user with the email does exist, return and error
		const user = new User({
			email: email,
			password: password
		});

		user.save(function(err){

			if(err) {
				return next(err);		
			}

			//Respond to request indicating the user was created
			res.json({ token: tokenForUser(user) });

		});


	});

}