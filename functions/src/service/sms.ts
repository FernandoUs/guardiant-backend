import * as functions from 'firebase-functions';
import twilio from 'twilio';

export class SmsService {
    private static twilioClient = twilio(
        functions.config().twilio.account_sid,
        functions.config().twilio.auth_token
    );

    private static TWILIO_PHONE = functions.config().twilio.phone_number;

    /**
     * Enviar código SMS de verificación
     */
    static async sendVerificationCode(phoneNumber: string): Promise<string> {
        try {
            const code = this.generateVerificationCode();
            
            const message = await this.twilioClient.messages.create({
                body: `Tu código de verificación Guardiant es: ${code}`,
                from: this.TWILIO_PHONE,
                to: phoneNumber
            });

            console.log(`✅ SMS enviado a ${phoneNumber}. SID: ${message.sid}`);
            
            return code;
        } catch (error: any) {
            console.error('❌ Error enviando SMS:', error);
            throw new Error(`Error enviando SMS: ${error.message}`);
        }
    }

    /**
     * Generar código de 6 dígitos
     */
    private static generateVerificationCode(): string {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }
}