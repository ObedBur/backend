import { defineConfig } from '@prisma/config';
import 'dotenv/config'; 

export default defineConfig({
  // Ici, schema attend directement le chemin vers le fichier
  schema: 'prisma/schema.prisma', 
  
  datasource: {
    url: process.env.DATABASE_URL,
  },
});