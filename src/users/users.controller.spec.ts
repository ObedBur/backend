import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { Role } from '@prisma/client';
import { RolesGuard } from '../common/guards/roles.guard';

const mockUsersService = {
  create: jest.fn(),
  findAll: jest.fn(),
  findOne: jest.fn(),
  findOneSafe: jest.fn(),
  update: jest.fn(),
  remove: jest.fn(),
};

describe('UsersController', () => {
  let controller: UsersController;
  let service: UsersService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    })
    .overrideGuard(RolesGuard)
    .useValue({ canActivate: () => true })
    .compile();

    controller = module.get<UsersController>(UsersController);
    service = module.get<UsersService>(UsersService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('create', () => {
    it('should create a user', async () => {
      const dto = {
        email: 'test@example.com',
        fullName: 'Test User',
        phone: '123456789',
        password: 'pwd',
        role: Role.CLIENT,
        city: 'Goma',
        isActive: true,
        isVerified: false,
      };
      mockUsersService.create.mockResolvedValue({ id: '1', ...dto });

      const result = await controller.create(dto);
      expect(result).toEqual({ id: '1', ...dto });
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(service.create).toHaveBeenCalledWith(dto);
    });
  });

  describe('findAll', () => {
    it('should return all users', async () => {
      mockUsersService.findAll.mockResolvedValue([]);
      const result = await controller.findAll();
      expect(result).toEqual([]);
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(service.findAll).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return a user without sensitive fields', async () => {
      mockUsersService.findOneSafe.mockResolvedValue({ id: '1' });
      const result = await controller.findOne('1');
      expect(result).toEqual({ id: '1' });
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(service.findOneSafe).toHaveBeenCalledWith('1');
    });
  });
});
