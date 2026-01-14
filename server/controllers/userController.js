import User from "../models/User.js";
import bcrypt from 'bcrypt.js';
import jwt from 'jsonwebtoken';

// Register User : /api/user/register
export const register = async (req, res)=> {
    try {
        const {name, email, password} = req.body;

        if (!name || !email || !password) {
            return res.json({success:false, message: 'Missing Details'})
        }

        const existingUser = await User.findOne({email})

        if (existingUser)
            return res.json({success:false, message: 'User already exists'})

        // if the user does not exist, create user 
        // when creating users, you have to encrypt the user's password
        const hashedPassword = await bcrypt.hash(password, 10)

        // create user data
        const user = await User.create({name, email, password: hashedPassword})
        
        // to authenicate the user, create token
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn:
        '7d'}); //token expires on a particular day - 7 days

        res.cookie('token', token, {
            httpOnly: true, // Prevent JavaScript  to access cookie
            secure: process.env.NODE_ENV === 'production', 
            //Use secure cookie in production
            sameSite: process.env.NODE_ENV === 'production' ? 'node' : 'strict', 
            // CSRF protection
            maxAge: 7 * 24 * 60 * 60 * 1000, // Cookie expiration time
        })
        return res.json({success:true, user: {email: user.email, name: user.name}})

    } catch (error) {
        console.log(error.message);
        res.json({success: false, message: error.message });
    }
}
