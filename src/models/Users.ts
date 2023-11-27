import {Model, DataTypes} from 'sequelize';
import {sequelize} from '../instances/pg';
import bcrypt from 'bcrypt';

export interface UserInstance extends Model{
    id: number;
    email: string;
    password: string;
}

export const User = sequelize.define<UserInstance>('User', {
    id:{
        primaryKey:true,
        autoIncrement: true,
        type: DataTypes.INTEGER
    },
    email:{
        type: DataTypes.STRING,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        set(value: string){
            let salt = bcrypt.genSaltSync(10);
            let hash = bcrypt.hashSync(value, salt);
            this.setDataValue('password', hash);
        }
        
        
    }
},{
    tableName: 'users',
    timestamps: false
})