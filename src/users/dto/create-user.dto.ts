import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsEnum,
  IsOptional,
  MinLength,
  Matches,
} from 'class-validator';
import { Role } from '@prisma/client';

export class CreateUserDto {
  @IsEmail({}, { message: "L'adresse email fournie n'est pas valide." })
  @IsNotEmpty({ message: "L'email est requis." })
  email: string;

  @IsString({
    message: 'Le mot de passe doit être une chaîne de caractères.',
  })
  @MinLength(8, {
    message: 'Le mot de passe doit contenir au moins 8 caractères.',
  })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message:
      'Le mot de passe doit contenir au moins une majuscule, une minuscule et un chiffre.',
  })
  @IsNotEmpty({ message: 'Le mot de passe est obligatoire.' })
  password: string;

  @IsString({
    message: 'Le nom complet doit être une chaîne de caractères.',
  })
  @IsNotEmpty({ message: 'Le nom complet est obligatoire.' })
  fullName: string;

  @IsString({
    message: 'Le numéro de téléphone doit être une chaîne de caractères.',
  })
  @IsNotEmpty({ message: 'Le numéro de téléphone est obligatoire.' })
  phone: string;

  @IsEnum(Role, { message: 'Le rôle doit être CLIENT, PROVIDER ou ADMIN.' })
  @IsOptional()
  role?: Role;

  @IsString({ message: 'La ville doit être une chaîne de caractères.' })
  @IsOptional()
  city?: string;
}
