import {Request, Response, NextFunction} from 'express';
import {User} from '../models/Users';
import JWT from 'jsonwebtoken';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';

dotenv.config();

export const Auth = {
    private: async (req: Request, res: Response, next: NextFunction) =>{
        let sucess = false;
        if(req.headers.authorization){

            const [authType, token] = req.headers.authorization.split(' ');
            if(authType === 'Bearer'){
                try{
                    const decoded = JWT.verify(
                        token, 
                        process.env.JWT_SECRET_KEY as string
                    );
                   sucess = true;       
                }catch(err){
                    console.log(err);
                }
            }
        }

        if(sucess){
            next();
            return;
        }
        res.status(403)
        res.json({error: 'Unauthorized'});
    }
}


/*
//BASIC AUTH
export const Auth = {
    private: async(req: Request, res: Response, next: NextFunction) =>{
        let sucess = false;
        //fazer verificações de AUTH
        if(req.headers.authorization){
            let hash: string = req.headers.authorization.substring(6)
            let decoded: string = Buffer.from(hash, 'base64').toString();
            let data = decoded.split(':');

            if(data.length === 2){
                const user = await User.findOne({ where: { email: data[0] } });
                if(user){
                    sucess = bcrypt.compareSync(data[1], user.password);
                }
            }
        }

        if(sucess){
            next();
            return;
        }
        
        res.status(401).json({error: 'Unauthorized'});
        return;
    }
}*/