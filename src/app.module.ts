import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';
import Redis from 'ioredis';
import { UsersModule } from './users/users.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { ThrottlerBehindProxyGuard } from './common/guards/throttler-behind-proxy.guard';
import { MailModule } from './mail/mail.module';
import { RedisModule } from './redis/redis.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => [
        {
          ttl: config.get('THROTTLE_TTL', 900000),
          limit: config.get('THROTTLE_LIMIT', 100),
          storage: new ThrottlerStorageRedisService(
            new Redis({
              host: config.get('REDIS_HOST', 'localhost'),
              port: config.get('REDIS_PORT', 6379),
            }),
          ),
        },
      ],
    }),
    PrismaModule,
    UsersModule,
    AuthModule,
    MailModule,
    RedisModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerBehindProxyGuard, // Utilise notre guard avec gestion de proxy
    },
  ],
})
export class AppModule {}
