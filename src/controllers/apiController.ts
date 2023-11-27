import { Request, Response } from 'express'
import JWT from 'jsonwebtoken'
import dotenv from 'dotenv'
import bcrypt from 'bcrypt';
import { User } from '../models/Users';

dotenv.config();

export const ping = (req: Request, res: Response) => {
    res.json({ pong: true });
}


export const register = async (req: Request, res: Response) => {
    if(req.body.email && req.body.password){
        let {email, password} = req.body;

        let hasUser = await User.findOne({where: {email}});
        if(hasUser) {
            res.status(400).json({error: 'User already exists'});
            return;
        
        }
        let newUser = await User.create({email, password});

        const token = JWT.sign(
            { id: newUser.id, email: newUser.email },
            process.env.JWT_SECRET_KEY as string,
            { expiresIn: '1d' },//expira em 1 dia
        )

        res.status(201)
        res.json({id: newUser.id, token});
        return;
    }
    res.json({error: 'Email and password are required'});
}


export const login = async (req: Request, res: Response) => {
    if(req.body.email && req.body.password){
        let {email, password}: {email: string, password: string} = req.body;

        let user = await User.findOne({where: {email}});
        if(user){
            let isValid = bcrypt.compareSync(password, user.password);
            if(isValid){
                const token = JWT.sign(
                    { id: user.id, email: user.email },
                    process.env.JWT_SECRET_KEY as string,
                    { expiresIn: '1d' },//expira em 1 dia
                )

                res.json({status: true, token});
                return;
            }
        }

        res.json({status: false});
        return;
    }
    res.json({error: 'Email and password are required'});
}

export const list = async (req: Request, res: Response) => {
    let users = await User.findAll();
    let list: string[] = [];

    for(let i in users){
        list.push(users[i].email);
    }

    res.json({list});
}