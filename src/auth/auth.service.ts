import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';

import { CreateUserDto, UpdateAuthDto, RegisterUserDto, LoginDto } from './dto';


import { Model } from 'mongoose';
import { User } from './entities/user.entity';

import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login.-response';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService,
   ) {

  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    //console.log(createUserDto);
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

  //Promise<LoginResponse>
  async register( registerUserDto: RegisterUserDto):Promise<LoginResponse> {
      //console.log({registerUserDto});
      //* Solución profe -- inicio
      const user = await this.create( registerUserDto );
      return {
        user,
        token: this.getJwt({id: user._id}),
      }
      //* Solución profe -- fin
      //? Esta fue mi solución utilizando el login, pero el profe hizo lo que yo iba a hacer al principio
      //! Creo el usuario
      //! como quiero que después de crear usuario genere sesión se llama al login.
      //! Por consiguiente obtengo el email y password de mi parametro para enviarlo al loggin
      /* 
      await this.create(registerUserDto);
      const { email, password } = registerUserDto;
      return await this.login({
        email,
        password
      }); */
  }

  async login( loginDto: LoginDto ): Promise<LoginResponse> {
    //console.log({loginDto});
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({email});
    if( !user ) throw new UnauthorizedException('Not valid credentials - email');
    if( !bcryptjs.compareSync(password, user.password ) ) throw new UnauthorizedException('Not valid credentials - password'); 
    
    const { password:_, ...rest } = user.toJSON();
    /**
     * User { _id, name, email, roles }
     * token -> Json web token
     */
    return {
      user: rest,
      token: this.getJwt({id: user.id}),
    }
    
  }

  //! JSON WEB TOKEN
  getJwt(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }
  //! que me regrese el usuario by Id
  async findUserById( userId: string ) {
    const user = await this.userModel.findById( userId );
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

}
