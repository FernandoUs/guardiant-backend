import { auth } from './firestore'; // <-- Importamos la instancia de auth
import { HttpsError } from 'firebase-functions/v1/https';

/**
 * Servicio encargado de manejar la creación de cuentas
 * utilizando Firebase Authentication.
 */
export class AuthService {

  /**
   * Registra un nuevo usuario con email y contraseña.
   */
  static async registerUser(
    email: string,
    password: string,
    displayName?: string
  ): Promise<{ success: boolean; message: string; userId?: string }> {
    try {
      // 1. Crear el usuario en Firebase Authentication
      const userRecord = await auth.createUser({
        email,
        password,
        displayName,
        emailVerified: false, // Inicia como no verificado
      });
      
      // 2. ELIMINAMOS LA GENERACIÓN DEL LINK AQUÍ
      // La app cliente (móvil o web) será responsable
      // de llamar a "user.sendEmailVerification()"
      // DESPUÉS de que el usuario inicie sesión por primera vez.

      return {
        success: true,
        message: 'Usuario registrado exitosamente.',
        userId: userRecord.uid
      };

    } catch (error: any) {
      console.error('Error al registrar usuario:', error);
      let message = 'Error desconocido al registrar.';
      
      if (error.code === 'auth/email-already-exists') {
        message = 'El correo electrónico ya está en uso.';
      } else if (error.code === 'auth/invalid-password') {
        message = 'La contraseña debe tener al menos 6 caracteres.';
      }
      
      throw new HttpsError('invalid-argument', message);
    }
  }

  
}

export default AuthService;