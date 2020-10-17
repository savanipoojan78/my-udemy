const config = require('config');

module.exports = function () {
        // config
    //console.log(!config.get('jwt_private'))
    if(!config.get('jwt_private')){
        /// will be handled and logged using error middleware 
        throw new Error('Fatal error: jwt_private is not defined !!');
    }

}