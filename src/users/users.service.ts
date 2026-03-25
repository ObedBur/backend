import {
  Injectable,
  NotFoundException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  /** Fields safe to return in API responses (no password/refreshToken). */
  private readonly safeSelect = {
    id: true,
    email: true,
    fullName: true,
    phone: true,
    role: true,
    city: true,
    isVerified: true,
    isActive: true,
    createdAt: true,
    updatedAt: true,
  } as const;

  constructor(private readonly prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto) {
    const existing = await this.prisma.user.findFirst({
      where: {
        OR: [
          { email: createUserDto.email },
          { phone: createUserDto.phone },
        ],
      },
    });

    if (existing) {
      throw new ConflictException(
        'Un utilisateur avec cet email ou téléphone existe déjà',
      );
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const data = { ...createUserDto, password: hashedPassword };

    const user = await this.prisma.user.create({ data });

    this.logger.log(
      `Nouvel utilisateur créé: ${user.email} (ID: ${user.id})`,
    );

    const { password: _pw, refreshToken: _rt, ...safeUser } = user;
    return safeUser;
  }

  async findAll(page = 1, limit = 20) {
    return this.prisma.user.findMany({
      where: { deletedAt: null },
      select: this.safeSelect,
      skip: (page - 1) * limit,
      take: limit,
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * Internal method — returns ALL fields including password & refreshToken.
   * Used by AuthService for credential verification.
   */
  async findOne(id: string) {
    const user = await this.prisma.user.findFirst({
      where: { id, deletedAt: null },
    });
    if (!user) throw new NotFoundException(`User with ID ${id} not found`);
    return user;
  }

  /** Public-safe version of findOne — excludes sensitive fields. */
  async findOneSafe(id: string) {
    const user = await this.prisma.user.findFirst({
      where: { id, deletedAt: null },
      select: this.safeSelect,
    });
    if (!user) throw new NotFoundException(`User with ID ${id} not found`);
    return user;
  }

  async findByEmail(email: string) {
    return this.prisma.user.findFirst({
      where: { email, deletedAt: null },
    });
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    await this.findOne(id); // Verify existence first

    // Re-hash password if it's being updated
    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(
        updateUserDto.password,
        10,
      );
    }

    return this.prisma.user.update({
      where: { id },
      data: updateUserDto,
      select: this.safeSelect,
    });
  }

  async updateByEmail(email: string, updateUserDto: UpdateUserDto) {
    const user = await this.findByEmail(email);
    if (!user) throw new NotFoundException(`User with email ${email} not found`);

    return this.prisma.user.update({
      where: { email },
      data: updateUserDto,
      select: this.safeSelect,
    });
  }

  async updateRefreshToken(id: string, refreshToken: string | null) {
    return this.prisma.user.update({
      where: { id },
      data: { refreshToken },
    });
  }

  async remove(id: string) {
    await this.findOne(id); // Verify existence first
    return this.prisma.user.update({
      where: { id },
      data: { deletedAt: new Date() },
      select: this.safeSelect,
    });
  }
}
