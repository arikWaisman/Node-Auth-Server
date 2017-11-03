const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//Create local strategy to handle signin 
const localOptions = { usernameField : 'email' }; //uses username by default we change it to email
const localLogin = new LocalStrategy( localOptions, function(email, password, done){
	//Verify this email and password, call done with the user
	//if it is the correct email and password
	//otherwise, call done with false
	User.findOne({ email: email }, function(err, user){

		//if there is an error with the db call return false
		if(err){
			return done(err, false);
		}

		//if the user wasnt found return false with null
		if(!user){
			return done(null, false);
		}

		//compare passwords os 'password' equal to user.password
		user.comparePassword(password, function(err, isMatch){

			if(err){
				return done(err)
			}

			if(!isMatch){
				return done(null, false)
			}

			return done(null, user);
		})
	});

});


//set up options for JWT Strategy
const jwtOptions = {
	jwtFromRequest: ExtractJwt.fromHeader('authorization'),
	secretOrKey: config.secret
}


//create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
	//see if the user id in the payload exists in our DB
	//if it does call done with that user otherwise call done without user object
	User.findById(payload.sub, function(err, user){

		//if there is an error with the db call return false
		if(err){
			return done(err, false);
		}

		if(user){
			//if user is found call done with user
			done(null, user)
		} else{
			//if user is not found call done with false. this is different
			//to the call in the err check since there was no error in the look up
			//just it would mean the user id that was encoding in the tokeb doesnt 
			//exist in the 
			done(null, false)
		}
	});
});


//tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);