import { ForbiddenException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client'
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
    constructor(private prismaService: PrismaService) { }

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

    login() {
        return { message: 'login' }
    }
}
