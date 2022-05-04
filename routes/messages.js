
const express= require('express');
const router = new express.Router();
const ExpressError = require('../expressError')
const Message = require('../models/message')
const {ensureLoggedIn, ensureCorrectUser} = require("../middleware/auth");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get('/:id', async(req,res,next)=>{
    try{
        let msg = await Message.get(req.params.id)
        return res.json({msg});

    }
    catch(e){
        return next(e)
    }
} )


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post('/', ensureLoggedIn, async(req,res,next)=>{
    try{
        let {from_username, to_username, body} = req.body
         let {msg} = await Message.create(from_username, to_username, body )
        return res.json({msg:'sent', msg})

    }
    catch(e){
        return next(e)
    }
})

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

 module.exports = router;