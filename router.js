const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

//by default passport tries to create a cookie, but since we use tokens we set it to false
const requireAuth = passport.authenticate('jwt', { session: false});
const requireSignin = passport.authenticate('local', { session: false });

module.exports = function(app){

	app.get('/', requireAuth, function(req, res){
		res.send({ message: 'super secret code is abc123' });
	});
	app.post('/signin', requireSignin, Authentication.signin);
	app.post('/signup', Authentication.signup)

}