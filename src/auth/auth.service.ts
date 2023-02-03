import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (user && (await bcrypt.compare(pass, user.password))) {
      return { id: user.id };
    }
    return null;
  }

  async login(user: { id: User['id'] }) {
    const payload = { sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async register(user: {
    email: User['email'];
    password: User['password'];
    details: User['details'];
  }) {
    const password = await bcrypt.hash(user.password, 10);

    const { id } = await this.prisma.user.create({
      data: {
        email: user.email,
        password,
        details: user.details,
      },
    });

    return this.login({ id });
  }
}
