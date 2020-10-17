const express = require('express');
const router = express.Router();
const {User , validate,validatePassword} = require('../models/user');
const _ = require('lodash');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('config');
const auth = require('../middleware/auth')
const crypto =require('crypto');
const Joi = require('joi');
// get current user 
router.get('/me',auth, async(req,res)=>{
    const id  = req.user._id;
    const user = await User.findById(id).select('-password').select('-__v'); /// excluding password
    res.send(user);
})
/// to reqister a user 
router.post('/',async (req,res)=>{
    const {error } = validate(req.body);
    if(error){
        res.status(400).send(error.details[0].message);
        return ;
    }
    let user = new User(_.pick(req.body, ['name','email','password']));
    try {
        const salt =await bcrypt.genSalt();
        user.password = await bcrypt.hash(user.password,12);
        const token = user.generateAuthToken();
        user = await user.save();
        user=  _.pick(user,['name','email']);
        res.header('x-auth-token',token).send(user);
    }
    catch(err){
        res.send('error in registering '+err.message);
    }

});
router.post('/forgetPassword',async(req,res,next)=>{
    const user=await User.findOne({email:req.body.email});
    if(!user){
        res.status(404).json({
            status:'error',
            msg:'UserMail Not Found Please Enter Correct Mail Id'
        })
        return ;
    }
    //2 generate a random reset token
    const resetToken=user.createPasswordResetToken();
    await user.save({validateBeforeSave:false})
    try{
        const resetLink=`${req.protocol}://${req.get('host')}/api/users/resetPassword/${resetToken}`;
        res.status(200).json({
            status:'success',
            message:'mail send Sucessfully',
            link: resetLink
        })
    }catch(err){
        user.passwordResetToken=undefined;
        await user.save({validateBeforeSave:false})
        res.status(400).json({
            status:'Failed',
            msg:'Error Generating link'
        })
    }
})
router.patch('/resetPassword/:resetToken',async(req,res)=>{
    const {error } = validatePassword(req.body);
    if(error){
        res.status(400).send(error.details[0].message);
        return ;
    }
    const encryptPasswordResetToken=crypto.createHash('sha256').update(req.params.resetToken).digest('hex');
    let user=await User.findOne( {passwordResetToken:encryptPasswordResetToken}
    )
    if(!user){
        res.status(400).json({
            status:'error',
            msg:'Forget Password link is Not Valid'
        })
        return;
    }
    user.passwordResetToken=undefined;
    user.password = await bcrypt.hash(user.password,12);
    await user.save();
    res.status(200).json({
        status:'success',
        msg:'password change successfully'
    })
})
module.exports = router ;