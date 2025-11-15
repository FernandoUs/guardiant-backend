import { db } from './firestore';
import { HttpsError } from 'firebase-functions/v1/https';
import { Timestamp } from 'firebase-admin/firestore';
import * as admin from 'firebase-admin';

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
      
      // 3. Enviar notificación push al dueño (si tiene FCM token)
      await this.sendPushNotification(
        userId,
        'Alerta de Seguridad',
        `Modo seguridad activado: ${this.getAlertTypeMessage(alertType)}`,
        { alertId: alertRef.id, alertType }
      );
      
      console.log(`✅ Modo seguridad activado para ${userId} por ${alertType}`);
      
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
        resolutionType: 'false_alarm',
        resolvedAt: Timestamp.now()
      });

      await batch.commit();

      // 3. Notificar a la app móvil que puede salir del modo camuflaje
      await this.sendCommandToDevice(userId, 'deactivate_security_mode', {
        alertId,
        resolutionType: 'false_alarm'
      });

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
   * Envía comando de bloqueo remoto al dispositivo.
   */
  static async remoteLockDevice(userId: string, alertId: string): Promise<any> {
    try {
      console.log(`[UserId: ${userId}] Solicitud de bloqueo remoto para la alerta ${alertId}`);
      
      // 1. Registrar el comando en la alerta
      await db
        .collection('users')
        .doc(userId)
        .collection('security_alerts')
        .doc(alertId)
        .update({
          'commands.lockDevice': {
            requestedAt: Timestamp.now(),
            status: 'pending'
          }
        });

      // 2. Enviar comando FCM al dispositivo
      const result = await this.sendCommandToDevice(userId, 'lock_device', {
        alertId,
        action: 'lock'
      });

      if (!result.success) {
        throw new HttpsError('unavailable', 'No se pudo enviar el comando al dispositivo');
      }

      return { 
        success: true, 
        message: 'Comando de bloqueo enviado al dispositivo' 
      };

    } catch (error: any) {
      console.error('Error en remoteLockDevice:', error);
      if (error instanceof HttpsError) throw error;
      throw new HttpsError('internal', error.message);
    }
  }

  /**
   * Envía comando de borrado de datos al dispositivo.
   */
  static async remoteWipeData(userId: string, alertId: string): Promise<any> {
    try {
      console.log(`[UserId: ${userId}] ⚠️ Solicitud de BORRADO DE DATOS para la alerta ${alertId}`);
      
      // 1. Registrar el comando en la alerta (CRÍTICO - Auditoría)
      await db
        .collection('users')
        .doc(userId)
        .collection('security_alerts')
        .doc(alertId)
        .update({
          'commands.wipeData': {
            requestedAt: Timestamp.now(),
            status: 'pending'
          }
        });

      // 2. Enviar comando FCM al dispositivo
      const result = await this.sendCommandToDevice(userId, 'wipe_data', {
        alertId,
        action: 'wipe',
        warning: 'Esta acción no se puede deshacer'
      });

      if (!result.success) {
        throw new HttpsError('unavailable', 'No se pudo enviar el comando al dispositivo');
      }

      return { 
        success: true, 
        message: 'Comando de borrado enviado. ADVERTENCIA: Esta acción es irreversible.' 
      };

    } catch (error: any) {
      console.error('Error en remoteWipeData:', error);
      if (error instanceof HttpsError) throw error;
      throw new HttpsError('internal', error.message);
    }
  }

  // ============================================
  // FUNCIONES AUXILIARES PARA FCM
  // ============================================

  /**
   * Envía una notificación push al usuario
   */
  private static async sendPushNotification(
    userId: string,
    title: string,
    body: string,
    data: any = {}
  ): Promise<{ success: boolean; message?: string }> {
    try {
      // Obtener el FCM token del usuario
      const userDoc = await db.collection('users').doc(userId).get();
      const userData = userDoc.data();
      
      if (!userData?.fcmToken) {
        console.warn(`⚠️ Usuario ${userId} no tiene FCM token registrado`);
        return { success: false, message: 'No FCM token' };
      }

      // Construir el mensaje
      const message: admin.messaging.Message = {
        notification: {
          title,
          body
        },
        data: {
          ...data,
          type: 'security_alert',
          timestamp: Date.now().toString()
        },
        token: userData.fcmToken,
        android: {
          priority: 'high',
          notification: {
            sound: 'default',
            channelId: 'security_alerts'
          }
        }
      };

      // Enviar el mensaje
      const response = await admin.messaging().send(message);
      console.log(`✅ Notificación enviada: ${response}`);
      
      return { success: true };

    } catch (error: any) {
      console.error('Error enviando notificación push:', error);
      
      // Si el token es inválido, limpiarlo de la BD
      if (error.code === 'messaging/invalid-registration-token' ||
          error.code === 'messaging/registration-token-not-registered') {
        await db.collection('users').doc(userId).update({
          fcmToken: null
        });
      }
      
      return { success: false, message: error.message };
    }
  }

  /**
   * Envía un comando de acción remota al dispositivo
   */
  private static async sendCommandToDevice(
    userId: string,
    command: string,
    payload: any = {}
  ): Promise<{ success: boolean; message?: string }> {
    try {
      // Obtener el FCM token del usuario
      const userDoc = await db.collection('users').doc(userId).get();
      const userData = userDoc.data();
      
      if (!userData?.fcmToken) {
        console.warn(`⚠️ Usuario ${userId} no tiene FCM token registrado`);
        return { success: false, message: 'No FCM token' };
      }

      // Construir mensaje de DATA (sin notificación visible)
      const message: admin.messaging.Message = {
        data: {
          command,
          payload: JSON.stringify(payload),
          timestamp: Date.now().toString()
        },
        token: userData.fcmToken,
        android: {
          priority: 'high'
        }
      };

      // Enviar el comando
      const response = await admin.messaging().send(message);
      console.log(`✅ Comando "${command}" enviado: ${response}`);
      
      return { success: true };

    } catch (error: any) {
      console.error(`Error enviando comando "${command}":`, error);
      
      // Si el token es inválido, limpiarlo
      if (error.code === 'messaging/invalid-registration-token' ||
          error.code === 'messaging/registration-token-not-registered') {
        await db.collection('users').doc(userId).update({
          fcmToken: null
        });
      }
      
      return { success: false, message: error.message };
    }
  }

  /**
   * Obtiene un mensaje legible según el tipo de alerta
   */
  private static getAlertTypeMessage(alertType: string): string {
    const messages: Record<string, string> = {
      'security_pin_used': 'PIN de seguridad utilizado',
      'abrupt_movement': 'Movimiento brusco detectado',
      'panic_button': 'Botón de pánico presionado',
      'repeated_failed_attempts': 'Múltiples intentos fallidos',
      'unauthorized_app_access': 'Intento de acceso no autorizado'
    };
    return messages[alertType] || 'Alerta de seguridad';
  }

  /**
 * Desactivar alerta cuando se desbloquea correctamente
 */
  static async deactivateAlertOnUnlock(
    userId: string,
    alertId: string
  ): Promise<any> {
    try {
        if (!alertId) {
            throw new HttpsError('invalid-argument', 'El ID de la alerta es requerido');
        }

        const userRef = db.collection('users').doc(userId);
        const alertRef = userRef.collection('security_alerts').doc(alertId);

        await alertRef.update({
            resolved: true,
            status: 'resolved',
            resolutionType: 'unlocked_successfully',
            resolvedAt: Timestamp.now()
        });

        console.log(`✅ Alerta ${alertId} desactivada por desbloqueo exitoso`);

        return { 
            success: true, 
            message: 'Alerta desactivada por desbloqueo exitoso' 
        };

    } catch (error: any) {
        console.error('Error desactivando alerta:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
  }
}

export default AlertsService;