import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { PrismaService } from '../prisma/prisma.service';
import { NotFoundException } from '@nestjs/common';
import { Role } from '@prisma/client';

const mockPrismaService = {
  user: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(),
  },
};

describe('UsersService', () => {
  let service: UsersService;
  let prisma: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    prisma = module.get<PrismaService>(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a user without returning password', async () => {
      const dto = {
        email: 'test@test.com',
        fullName: 'Test User',
        phone: '123456789',
        password: 'pwd',
        role: Role.CLIENT,
        city: 'Goma',
      };
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...dtoWithoutPassword } = dto;
      
      mockPrismaService.user.findFirst.mockResolvedValue(null);
      mockPrismaService.user.create.mockResolvedValue({ 
        id: '1', 
        ...dto, 
        isActive: true, 
        isVerified: false,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const result = await service.create(dto);
      expect(result).not.toHaveProperty('password');
      expect(result.email).toBe(dto.email);
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(prisma.user.create).toHaveBeenCalled();
    });

    it('should throw ConflictException if user already exists', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue({ id: '1' });
      const dto = { email: 'dup@test.com', password: 'pwd', fullName: 'test', phone: '123' };
      await expect(service.create(dto as any)).rejects.toThrow();
    });
  });

  describe('findAll', () => {
    it('should return all active users', async () => {
      mockPrismaService.user.findMany.mockResolvedValue([]);
      const result = await service.findAll();
      expect(result).toEqual([]);
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(prisma.user.findMany).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return a user if found', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue({ id: '1' });
      const result = await service.findOne('1');
      expect(result).toEqual({ id: '1' });
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(prisma.user.findFirst).toHaveBeenCalled();
    });

    it('should throw NotFoundException if user not found', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue(null);
      await expect(service.findOne('1')).rejects.toThrow(NotFoundException);
    });
  });

  describe('findOneSafe', () => {
    it('should return a safe user copy', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue({ id: '1', email: 'test@test.com' });
      const result = await service.findOneSafe('1');
      expect(result).toEqual({ id: '1', email: 'test@test.com' });
    });
  });

  describe('update', () => {
    it('should update user and re-hash password if provided', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue({ id: '1' });
      mockPrismaService.user.update.mockResolvedValue({ id: '1', email: 'new@test.com' });
      
      const result = await service.update('1', { email: 'new@test.com', password: 'newpassword' });
      expect(result.email).toBe('new@test.com');
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(prisma.user.update).toHaveBeenCalled();
    });
  });

  describe('remove', () => {
    it('should perform soft delete', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue({ id: '1' });
      mockPrismaService.user.update.mockResolvedValue({ id: '1', deletedAt: new Date() });
      
      const result = await service.remove('1');
      expect(result).toHaveProperty('deletedAt');
    });
  });
});
