import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BrevoClient } from '@getbrevo/brevo';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private client: BrevoClient;

  constructor(private configService: ConfigService) {
    this.client = new BrevoClient({
      apiKey: this.configService.getOrThrow<string>('BREVO_API_KEY'),
    });
  }

  async sendVerificationEmail(email: string, fullName: string, otp: string) {
    try {
      const result = await this.client.transactionalEmails.sendTransacEmail({
        subject: 'Vérification de votre compte - Kaskade',
        to: [{ email: email, name: fullName }],
        sender: {
          email: this.configService.get<string>('MAIL_FROM_EMAIL'),
          name: this.configService.get<string>('MAIL_FROM_NAME'),
        },
        htmlContent: `
          <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
              <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                <h1 style="color: #007bff; text-align: center;">Bienvenue chez Kaskade !</h1>
                <p>Bonjour <strong>${fullName}</strong>,</p>
                <p>Merci de vous être inscrit. Pour activer votre compte, veuillez utiliser le code de vérification suivant :</p>
                <div style="text-align: center; margin: 30px 0;">
                  <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; background: #f8f9fa; padding: 15px 30px; border-radius: 5px; border: 1px dashed #007bff; color: #007bff;">
                    ${otp}
                  </span>
                </div>
                <p>Ce code est valable pendant <strong>10 minutes</strong>. Si vous n'avez pas créé de compte, vous pouvez ignorer cet e-mail en toute sécurité.</p>
                <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="font-size: 12px; color: #777; text-align: center;">&copy; 2026 Kaskade App. Tous droits réservés.</p>
              </div>
            </body>
          </html>
        `,
      });
      this.logger.log(`E-mail de vérification envoyé à ${email}`);
      return result;
    } catch (error) {
      this.logger.error(`Erreur lors de l'envoi de l'e-mail à ${email}:`, error);
      throw error;
    }
  }

  async sendPasswordResetEmail(email: string, fullName: string, token: string) {
    const resetUrl = `${this.configService.get('FRONTEND_URL') || 'http://localhost:3000'}/reset-password?token=${token}`;

    try {
      await this.client.transactionalEmails.sendTransacEmail({
        subject: 'Réinitialisation de votre mot de passe - Kaskade',
        to: [{ email: email, name: fullName }],
        sender: {
          email: this.configService.get<string>('MAIL_FROM_EMAIL'),
          name: this.configService.get<string>('MAIL_FROM_NAME'),
        },
        htmlContent: `
          <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
              <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                <h1 style="color: #dc3545; text-align: center;">Réinitialisation de mot de passe</h1>
                <p>Bonjour <strong>${fullName}</strong>,</p>
                <p>Vous avez demandé la réinitialisation de votre mot de passe. Cliquez sur le bouton ci-dessous pour continuer :</p>
                <div style="text-align: center; margin: 30px 0;">
                  <a href="${resetUrl}" style="background-color: #007bff; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                    Réinitialiser mon mot de passe
                  </a>
                </div>
                <p>Si vous n'avez pas demandé cela, veuillez ignorer cet e-mail. Votre mot de passe restera inchangé.</p>
                <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="font-size: 12px; color: #777; text-align: center;">&copy; 2026 Kaskade App. Tous droits réservés.</p>
              </div>
            </body>
          </html>
        `,
      });
      this.logger.log(`E-mail de réinitialisation envoyé à ${email}`);
    } catch (error) {
      this.logger.error(`Erreur lors de l'envoi du reset e-mail à ${email}:`, error);
      throw error;
    }
  }
}
