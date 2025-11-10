import { db } from './firestore';
import { HttpsError } from 'firebase-functions/v1/https';
import { Timestamp } from 'firebase-admin/firestore';

/**
 * Servicio encargado de manejar el perfil principal del usuario
 * y lecturas de actividad.
 */
export class UsersService {

  /**
   * Obtiene el estado del setup desde el documento principal del usuario.
   */
  static async getSetupStatus(userId: string): Promise<any> {
    try {
      const userDoc = await db.collection('users').doc(userId).get();

      if (!userDoc.exists) {
        throw new HttpsError('not-found', 'Usuario no encontrado');
      }

      const userData = userDoc.data();
      return {
        success: true,
        data: {
          setup: userData?.setup || {},
          currentMode: userData?.currentMode || 'normal',
          security: userData?.security || {}
        }
      };
    } catch (error: any) {
      console.error('Error en getSetupStatus:', error);
      if (error instanceof HttpsError) {
        throw error;
      }
      throw new HttpsError('internal', error.message);
    }
  }

  /**
   * Actualiza el perfil de un usuario (nombre, teléfono, contactos).
   */
  static async updateUserProfile(userId: string, data: any): Promise<any> {
    const { displayName, phoneNumber, emergencyContacts } = data;

    try {
      const updateData: any = {
        updatedAt: Timestamp.now()
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

      await db.collection('users').doc(userId).update(updateData);

      return {
        success: true,
        message: 'Perfil actualizado correctamente'
      };
    } catch (error: any) {
      console.error('Error en updateUserProfile:', error);
      if (error instanceof HttpsError) {
        throw error;
      }
      throw new HttpsError('internal', error.message);
    }
  }

  /**
   * Obtiene los registros de actividad (desbloqueos, intentos fallidos)
   */
  static async getActivityFeed(userId: string): Promise<any> {
    try {
      // Traemos los últimos 10 desbloqueos
      const unlocksSnap = await db
        .collection('users')
        .doc(userId)
        .collection('unlock_history')
        .limit(10) // <-- Límite para no traer miles
        .get();

      // Traemos los últimos 10 intentos fallidos
      const failedSnap = await db
        .collection('users')
        .doc(userId)
        .collection('failed_attempts')
        .limit(10)
        .get();

      const unlocks = unlocksSnap.docs.map(doc => doc.data());
      const failedAttempts = failedSnap.docs.map(doc => doc.data());

      // (Aquí podrías combinar y ordenar los 2 arrays por fecha si quisieras)

      return {
        success: true,
        data: {
          unlocks,
          failedAttempts
        }
      };

    } catch (error: any) {
      console.error('Error en getActivityFeed:', error);
      throw new HttpsError('internal', error.message);
    }
  }

  /**
   * Obtiene las alertas de seguridad activas
   */
  static async getSecurityAlerts(userId: string): Promise<any> {
    try {
      // Traemos solo las alertas que no han sido resueltas
      const alertsSnap = await db
        .collection('users')
        .doc(userId)
        .collection('security_alerts')
        .where('resolved', '==', false)
        .limit(10)
        .get();
      
      const alerts = alertsSnap.docs.map(doc => ({ id: doc.id, ...doc.data() }));

      return {
        success: true,
        data: {
          alerts
        }
      };

    } catch (error: any) {
      console.error('Error en getSecurityAlerts:', error);
      throw new HttpsError('internal', error.message);
    }
  }

  // ============================================
  // NUEVA FUNCIÓN PARA EL DIAGRAMA DE SEGURIDAD
  // ============================================

  /**
   * Registra un evento de seguridad genérico (ej. intento fallido de app)
   * Esto es llamado por la app cliente cuando detecta actividad sospechosa.
   */
  static async logSecurityEvent(
    userId: string, 
    eventType: string, 
    details: any
  ): Promise<any> {
    try {
      if (!eventType) {
        throw new HttpsError('invalid-argument', 'El tipo de evento es requerido');
      }

      await db
        .collection('users')
        .doc(userId)
        .collection('security_alerts')
        .add({
          type: eventType,
          details: details || {}, // Guarda los detalles (location, appName, etc.)
          timestamp: Timestamp.now(),
          status: 'active',
          resolved: false 
        });

      return { success: true, message: 'Evento de seguridad registrado' };

    } catch (error: any) {
      console.error('Error en logSecurityEvent:', error);
      if (error instanceof HttpsError) throw error;
      throw new HttpsError('internal', error.message);
    }
  }
}

export default UsersService;