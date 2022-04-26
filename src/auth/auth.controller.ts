import { Body, Controller, HttpCode, ParseIntPipe, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('register')
    register(@Body() dto: AuthDto) {
        return this.authService.register(dto)
    }

    @Post('login')
    @HttpCode(200)
    login(@Body() dto: AuthDto) {
        return this.authService.login(dto)
    }
}
