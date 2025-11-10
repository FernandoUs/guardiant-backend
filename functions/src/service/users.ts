import { db, auth } from './firestore'; // <-- Importamos db y auth
import * as admin from 'firebase-admin'; // <-- Lo mantenemos para admin.firestore.Timestamp
import { HttpsError } from 'firebase-functions/v1/https';


/**
 * Servicio para gestionar perfiles de usuario y su estado.
 */
export class UsersService {

  /**
   * Obtiene el estado de configuración (setup) y el modo actual del usuario.
   * (Lógica movida desde getSetupStatus en index.ts)
   */
  static async getSetupStatus(userId: string): Promise<{ 
    setup: any; 
    currentMode: string; 
    security: any; 
  }> {
    try {
      const userDoc = await db.collection('users').doc(userId).get();

      if (!userDoc.exists) {
        throw new HttpsError('not-found', 'Usuario no encontrado');
      }

      const userData = userDoc.data();

      // Devuelve la data tal como la esperaba tu 'index.ts'
      return {
        setup: userData?.setup || {},
        currentMode: userData?.currentMode || 'normal',
        security: userData?.security || {}
      };

    } catch (error: any) {
      console.error(`Error en getSetupStatus para ${userId}:`, error);
      if (error instanceof HttpsError) {
        throw error;
      }
      throw new HttpsError('internal', 'Error al obtener el estado del usuario.');
    }
  }

  /**
   * Actualiza el perfil de un usuario con datos como displayName o emergencyContacts.
   * (Lógica movida desde updateUserProfile en index.ts)
   */
  static async updateUserProfile(userId: string, data: any): Promise<{ 
    success: boolean; 
    message: string; 
  }> {
    const { displayName, phoneNumber, emergencyContacts } = data;

    try {
      const updateData: any = {
        updatedAt: admin.firestore.Timestamp.now()
      };

      if (displayName !== undefined) {
        updateData.displayName = displayName;
      }

      if (phoneNumber !== undefined) {
        updateData.phoneNumber = phoneNumber;
      }

      if (emergencyContacts !== undefined) {
        if (!Array.isArray(emergencyContacts)) {
          throw new HttpsError(
            'invalid-argument',
            'emergencyContacts debe ser un array'
          );
        }
        updateData.emergencyContacts = emergencyContacts;
      }

      // Actualizar también el registro de Auth si el displayName cambió
      if (displayName !== undefined) {
        await auth.updateUser(userId, { displayName }); // <-- Usamos la instancia importada
      }

      await db.collection('users').doc(userId).update(updateData);

      return {
        success: true,
        message: 'Perfil actualizado correctamente'
      };

    } catch (error: any) {
      console.error(`Error en updateUserProfile para ${userId}:`, error);
      if (error instanceof HttpsError) {
        throw error;
      }
      throw new HttpsError('internal', 'Error al actualizar el perfil.');
    }
  }
}

export default UsersService;