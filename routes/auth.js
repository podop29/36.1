
const express= require('express');
const router = new express.Router();
const ExpressError = require('../expressError')
const User = require("../models/user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { user } = require('pg/lib/defaults');


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post('/login', async(req,res,next)=>{
    try{
        const {username, password} = req.body;
        if(!username || !password){
            throw new ExpressError("Username and Password required", 400)
          }


        if(await User.authenticate(username,password)){
            let token = jwt.sign({username}, SECRET_KEY)
            User.updateLoginTimestamp(username);
            return res.json({msg: "Logged in", token})
        }
        else{
            throw new ExpressError("Username not found", 404)
        }


    }catch(e){
        return next(e)
    }
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async(req,res,next)=>{
    try{
        let {username} = await User.register(req.body);
        let token = jwt.sign({username}, SECRET_KEY);
        User.updateLoginTimestamp(username);
        return res.json({token})
    }catch(e){
        return next(e)
    }
})


 module.exports = router;