import { db } from './firestore';
import { HttpsError } from 'firebase-functions/v1/https';
import { Timestamp } from 'firebase-admin/firestore';

/**
 * Servicio encargado de manejar las acciones remotas
 * y los estados de alerta.
 */
export class AlertsService {

  /**
   * Activa el modo seguridad.
   * Esta es la función central llamada por:
   * 1. PIN de seguridad (desde config.ts)
   * 2. Movimiento brusco (desde index.ts)
   * 3. Botón de pánico web (desde index.ts)
   */
  static async activateSecurityMode(
    userId: string, 
    alertType: string, 
    details: any = {}
  ): Promise<any> {
    try {
      const userRef = db.collection('users').doc(userId);
      
      // 1. Crear la alerta de seguridad
      const alertRef = userRef.collection('security_alerts').doc();
      const alertData = {
        type: alertType,
        timestamp: Timestamp.now(),
        status: 'active',
        resolved: false,
        details: {
          ...details,
          triggeredBy: alertType,
        },
      };

      // 2. Actualizar estado del usuario
      const userUpdate = {
        currentMode: 'security',
        'security.alertActive': true,
        'security.modeActivatedAt': Timestamp.now(),
        updatedAt: Timestamp.now()
      };

      // Usamos un batch para asegurar consistencia
      const batch = db.batch();
      batch.set(alertRef, alertData);
      batch.update(userRef, userUpdate);
      
      await batch.commit();
      
      // TODO: Enviar notificación (Email/SMS) al dueño
      // (Aquí iría la lógica de SendGrid o Twilio)
      console.log(`Modo seguridad activado para ${userId} por ${alertType}`);
      
      return { 
        success: true, 
        message: 'Modo seguridad activado', 
        alertId: alertRef.id 
      };

    } catch (error: any) {
      console.error('Error en activateSecurityMode:', error);
      if (error instanceof HttpsError) throw error;
      throw new HttpsError('internal', error.message);
    }
  }

  /**
   * Desactiva el modo seguridad.
   * Llamado por el dueño desde el panel web ("Falsa Alarma").
   */
  static async deactivateSecurityMode(userId: string, alertId: string): Promise<any> {
    try {
      if (!alertId) {
        throw new HttpsError('invalid-argument', 'El ID de la alerta es requerido');
      }

      const userRef = db.collection('users').doc(userId);
      const alertRef = userRef.collection('security_alerts').doc(alertId);

      const batch = db.batch();

      // 1. Actualizar el documento principal del usuario
      batch.update(userRef, {
        currentMode: 'normal',
        'security.alertActive': false,
        'security.modeActivatedAt': null,
        updatedAt: Timestamp.now()
      });

      // 2. Marcar la alerta como resuelta
      batch.update(alertRef, {
        resolved: true,
        status: 'resolved',
        resolutionType: 'false_alarm'
      });

      await batch.commit();

      return { 
        success: true, 
        message: 'Modo seguridad desactivado. Falsa alarma registrada.' 
      };

    } catch (error: any) {
      console.error('Error en deactivateSecurityMode:', error);
      if (error instanceof HttpsError) throw error;
      throw new HttpsError('internal', error.message);
    }
  }

  /**
   * [Marcador] Envía comando de bloqueo remoto al dispositivo.
   */
  static async remoteLockDevice(userId: string, alertId: string): Promise<any> {
    console.log(`[UserId: ${userId}] Solicitud de bloqueo remoto para la alerta ${alertId}`);
    // Lógica de FCM (Firebase Cloud Messaging) iría aquí
    return { 
      success: true, 
      message: 'Comando de bloqueo enviado (implementación pendiente)' 
    };
  }

  /**
   * [Marcador] Envía comando de borrado de datos al dispositivo.
   */
  static async remoteWipeData(userId: string, alertId: string): Promise<any> {
    console.log(`[UserId: ${userId}] Solicitud de BORRADO DE DATOS para la alerta ${alertId}`);
    // Lógica de FCM iría aquí
    return { 
      success: true, 
      message: 'Comando de borrado de datos enviado (implementación pendiente)' 
    };
  }
}

export default AlertsService;