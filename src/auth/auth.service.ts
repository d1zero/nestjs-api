import { ForbiddenException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client'
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(
        private prismaService: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) { }

    async register(dto: AuthDto) {
        // generate password hash
        const hash = await argon.hash(dto.password);

        // save new user in db
        try {
            const user = await this.prismaService.user.create({
                data: {
                    email: dto.email, hash
                },
            })

            delete user.hash;
            // return saved user
            return user
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials already taken')
                }
            }
            throw error
        }
    }

    async login(dto: AuthDto) {
        // find user by email
        const user = await this.prismaService.user.findUnique({
            where: {
                email: dto.email
            }
        })

        // if user does not exist throw exception
        if (!user) throw new ForbiddenException('Credentials incorrect')
        // if password is incorrect throw exception
        const pswdMatches = await argon.verify(user.hash, dto.password)
        if (!pswdMatches) throw new ForbiddenException('Credentials incorrect')

        return this.signToken(user.id, user.email)
    }

    async signToken(userId: number, email: string): Promise<{ access: string }> {
        const data = {
            sub: userId,
            email
        }

        const token = await this.jwt.signAsync(data, { expiresIn: '15m', secret: this.config.get('JWT_SECRET') })
        return { access: token }
    }
}
