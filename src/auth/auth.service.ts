import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';

import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService,
   ) {

  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    console.log(createUserDto);
    //! Insertar de manera básica en nuestra BD
    
    try {
      const { password, ...userData } = createUserDto;
      //! 1. encriptar la contraseña descargamos este paquete para encriptar npm i bcryptjs y npm i --save-dev @types/bcryptjs para que funcione en ts
      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });
      //! 2. guardar el usuario
      /* const newUser = new this.userModel( createUserDto );
      return await newUser.save(); */
      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if( error.code === 11000 ) throw new BadRequestException(`${createUserDto.email} already exists!`)
      throw new InternalServerErrorException('Something terrible happen!!');
    }

  }

  async login( loginDto: LoginDto ) {
    console.log({loginDto});
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({email});
    if( !user ) throw new UnauthorizedException('Not valid credentials - email');
    if( !bcryptjs.compareSync(password, user.password ) ) throw new UnauthorizedException('Not valid credentials - password'); 
    
    const { password:_, ...rest } = user.toJSON();
    return {
      user: rest,
      token: this.getJwt({id: user.id}),
    }
    /**
     * User { _id, name, email, roles }
     * token -> Json web token
     */
  }

  //! JSON WEB TOKEN
  getJwt(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
