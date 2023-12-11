import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from "bcryptjs";

import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { JwtService } from '@nestjs/jwt';
import { LoginResponse } from './interfaces/login-response';
import { CreateUserDto, RegisterUserDto, LoginDto, UpdateAuthDto } from './dto';

@Injectable()
export class AuthService {


  constructor(
    @InjectModel( User.name ) private userModel: Model<User>, 
    private jwtService: JwtService
  ){}

  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {

      //1. Encriptar la contraseña
      const { password, ...userData } = createUserDto;
    
      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });

      //2. Guardar uruario
      await newUser.save();

      const { password:_, ...user } = newUser.toJSON();
      //3. Generat JWT (json web tocken)

      return user;
      
      //4. manejar errores o excesiones
    } catch (error) {
      if( error.code === 11000 ) {
        throw new BadRequestException(`${ createUserDto.email } already exists!`)
      }
      throw new InternalServerErrorException('Something terribe happen!!!');
    }

  }

  async register( registerUserDto: RegisterUserDto ) : Promise<LoginResponse>{

    //En caso de que tengan propuedades diferentes
    //const user2 = await this.create({ email: registerUserDto.email, name: registerUserDto.name, password: registerUserDto.password});

    const user = await this.create( registerUserDto );
    console.log({ user })


    return{
      user: user,
      token: this.getJwtToken({ id: user._id })
    }
  }

  async login( loginDto: LoginDto ) : Promise<LoginResponse>{

    //Verificacion de Usuario
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email: email })

    if( !user ) {
      throw new UnauthorizedException( 'Not valid credentials - email' )
    }
    if( !bcryptjs.compareSync( password, user.password ) ){
      throw new UnauthorizedException( 'Not valid credentials - password' )
    }

    const { password:_, ...rest} = user.toJSON()

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id })
    }

    //return 'Todo Bien!'
    /**
     * User { _id, name, email, roles }
     * Token -> token de acceso,JWT
     */
  }

  findAll(): Promise<User[]>{
    return  this.userModel.find();
  }

  async finfUserById(userId: string ) {
    const user = await this.userModel.findById(userId);

    const {password, ...rest} = user.toJSON()
    return rest;
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

  //1. Generar el Token y crear la interfaz que de los datos que son necesarios para cargar al usuario
  //2. en la funcion login retorno return {user: rest,token: this.getJwtToken({ id: user.id })}
  //3. en el .env crear la llave para poder generar el token
  getJwtToken( payload: JwtPayload ){
    const token = this.jwtService.sign(payload);
    return token;
  }
}
