import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '../../generated/prisma';
import { LoginUserDto, RegisterUserDto } from './dto';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('AuthService');

    constructor(
        private jwtService: JwtService
    ) { super() }

    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async signJWT(payload: JWTPayload) {
        return this.jwtService.sign(payload);
    }

    async registerUser(registerUserDto: RegisterUserDto) {

        const { email, password, name } = registerUserDto;

        try {

            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }

            const newUser = await this.user.create({
                data: {
                    email: email,
                    password: bcrypt.hashSync(password, 10),
                    name: name,
                }
            });

            const { password: __, ...rest } = newUser;

            return {
                user: rest,
                token: await this.signJWT(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {

        const { email, password } = loginUserDto;

        try {

            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }

            const { password: __, ...rest } = user;

            return {
                user: rest,
                token: await this.signJWT(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }
}
