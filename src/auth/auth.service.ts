import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { JwtPayload } from '../common/interfaces/jwt-payload.interface';
import { MailService } from '../mail/mail.service';
import { RedisService } from '../redis/redis.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly redisService: RedisService,
  ) {}

  async register(createUserDto: CreateUserDto) {
    const user = await this.usersService.create(createUserDto);
    
    // Génération OTP (6 chiffres)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Stockage dans Redis (Expire après 10 min)
    await this.redisService.set(`otp:${user.email}`, otp, 600);
    
    // Envoi de l'e-mail via Brevo
    try {
      await this.mailService.sendVerificationEmail(user.email, user.fullName, otp);
    } catch (error) {
      this.logger.error(`Échec de l'envoi de l'e-mail à ${user.email}`, error);
      // On continue quand même, l'utilisateur pourra demander un renvoi d'OTP plus tard
    }

    return {
      message: 'Inscription réussie. Veuillez vérifier votre boîte e-mail pour activer votre compte.',
      userId: user.id,
      email: user.email,
    };
  }

  async verifyOtp(email: string, otp: string) {
    const storedOtp = await this.redisService.get(`otp:${email}`);
    
    if (!storedOtp || storedOtp !== otp) {
      throw new BadRequestException('Code de vérification invalide ou expiré');
    }

    // Activer l'utilisateur
    await this.usersService.updateByEmail(email, { isVerified: true });
    
    // Supprimer l'OTP
    await this.redisService.del(`otp:${email}`);

    return { message: 'Compte vérifié avec succès. Vous pouvez maintenant vous connecter.' };
  }

  async login(loginDto: LoginDto) {
    const user = await this.usersService.findByEmail(loginDto.email);

    if (!user) {
      throw new UnauthorizedException('Identifiants incorrects');
    }

    // Vérifier si l'utilisateur est vérifié (Brevo Flow)
    if (!user.isVerified) {
      throw new UnauthorizedException('Veuillez vérifier votre compte par e-mail avant de vous connecter.');
    }

    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Identifiants incorrects');
    }

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };
    const tokens = await this.getTokens(payload);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    this.logger.log(`Connexion réussie: ${user.email} (ID: ${user.id})`);

    const {
      password: _pw,
      refreshToken: _rt,
      ...userWithoutSecrets
    } = user;

    return {
      message: 'Connexion réussie',
      user: userWithoutSecrets,
      tokens,
    };
  }

  async resendOtp(email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new BadRequestException('Utilisateur non trouvé');
    if (user.isVerified) throw new BadRequestException('Compte déjà vérifié');

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await this.redisService.set(`otp:${email}`, otp, 600);

    await this.mailService.sendVerificationEmail(email, user.fullName, otp);

    return { message: 'Un nouveau code de vérification a été envoyé à votre adresse e-mail.' };
  }

  async logout(userId: string) {
    await this.usersService.updateRefreshToken(userId, null);
    this.logger.log(
      `Déconnexion réussie pour l'utilisateur ID: ${userId}`,
    );
    return { message: 'Déconnexion réussie' };
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.usersService.findOne(userId);

    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Accès refusé');
    }

    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      user.refreshToken,
    );
    if (!refreshTokenMatches) {
      throw new ForbiddenException('Accès refusé');
    }

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };
    const tokens = await this.getTokens(payload);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  private async updateRefreshToken(
    userId: string,
    refreshToken: string | null,
  ) {
    if (refreshToken) {
      refreshToken = await bcrypt.hash(refreshToken, 10);
    }
    await this.usersService.updateRefreshToken(userId, refreshToken);
  }

  private async getTokens(payload: JwtPayload) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return { accessToken, refreshToken };
  }
}
