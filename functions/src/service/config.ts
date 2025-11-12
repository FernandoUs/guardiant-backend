import { db } from './firestore';
import * as bcrypt from 'bcryptjs';
import { Timestamp, FieldValue } from 'firebase-admin/firestore';
import AlertsService from './alerts';

interface PinConfiguration {
  normalPinHash: string;
  securityPinHash: string;
  createdAt: Timestamp;
  lastUpdated: Timestamp;
}

interface AppConfiguration {
  packageName: string;
  appName: string;
  icon?: string | null;
  isProtected: boolean;
  addedAt: Timestamp;
}

export class ConfigService {
  
  /**
   * Guardar configuración inicial de PINs
   */
  static async savePins(
    userId: string,
    normalPin: string,
    securityPin: string
  ): Promise<{ success: boolean; message: string }> {
    try {
      // Validaciones
      if (!normalPin || !securityPin) {
        return { success: false, message: 'Ambos PINs son requeridos' };
      }
      if (normalPin.length < 4 || normalPin.length > 6) {
        return { success: false, message: 'El PIN debe tener entre 4 y 6 dígitos' };
      }
      if (normalPin === securityPin) {
        return { success: false, message: 'Los PINs deben ser diferentes' };
      }
      if (!/^\d+$/.test(normalPin) || !/^\d+$/.test(securityPin)) {
        return { success: false, message: 'Los PINs solo deben contener números' };
      }

      // Hashear PINs
      const normalPinHash = await bcrypt.hash(normalPin, 10);
      const securityPinHash = await bcrypt.hash(securityPin, 10);

      // Guardar en Firestore
      await db
        .collection('users')
        .doc(userId)
        .collection('config')
        .doc('pins')
        .set({
          normalPinHash,
          securityPinHash,
          createdAt: Timestamp.now(),
          lastUpdated: Timestamp.now()
        }, { merge: true });

      // Actualizar usuario principal
      await db
        .collection('users')
        .doc(userId)
        .update({
          'setup.pinsConfigured': true,
          'setup.lastStep': 'pins',
          updatedAt: Timestamp.now()
        });

      return { success: true, message: 'PINs guardados exitosamente' };

    } catch (error) {
      console.error('Error guardando PINs:', error);
      return { success: false, message: 'Error guardando configuración' };
    }
  }

  /**
   * Verificar PIN (para login en la app)
   */
  static async verifyPin(
    userId: string,
    pin: string
  ): Promise<{ 
    success: boolean; 
    mode: 'normal' | 'security' | null;
    message: string;
  }> {
    try {
      const pinsDoc = await db
        .collection('users')
        .doc(userId)
        .collection('config')
        .doc('pins')
        .get();

      if (!pinsDoc.exists) {
        return { success: false, mode: null, message: 'Configuración no encontrada' };
      }

      const { normalPinHash, securityPinHash } = pinsDoc.data() as PinConfiguration;

      // Verificar PIN normal
      const isNormalPin = await bcrypt.compare(pin, normalPinHash);
      if (isNormalPin) {
        await this.logUnlock(userId, 'normal');
        return { success: true, mode: 'normal', message: 'PIN normal correcto' };
      }

      // Verificar PIN de seguridad
      const isSecurityPin = await bcrypt.compare(pin, securityPinHash);
      if (isSecurityPin) {
        
        // Activar modo seguridad
        await AlertsService.activateSecurityMode(
          userId, 
          'security_pin_used',
          { pinUsed: `${pin.length} digits` }
        );
        
        return {
          success: true,
          mode: 'security',
          message: 'PIN de seguridad correcto - Modo camuflaje activado'
        };
      }

      // PIN incorrecto
      await this.logFailedAttempt(userId, pin.length);
      return { success: false, mode: null, message: 'PIN incorrecto' };

    } catch (error) {
      console.error('Error verificando PIN:', error);
      return { success: false, mode: null, message: 'Error en verificación' };
    }
  }

  /**
   * Guardar apps protegidas
   */
  static async saveProtectedApps(
    userId: string,
    apps: { packageName: string; appName: string; icon?: string }[]
  ): Promise<{ success: boolean; message: string }> {
    try {
      const protectedApps: AppConfiguration[] = apps.map(app => ({
        packageName: app.packageName,
        appName: app.appName,
        icon: app.icon || null,
        isProtected: true,
        addedAt: Timestamp.now()
      }));

      await db
        .collection('users')
        .doc(userId)
        .collection('config')
        .doc('apps')
        .set({
          protectedApps,
          totalProtected: apps.length,
          lastUpdated: Timestamp.now()
        });

      // Marcar setup como completo (ya no hay paso de "protectionLevel")
      await db
        .collection('users')
        .doc(userId)
        .update({
          'setup.appsConfigured': true,
          'setup.completed': true, // ← Ya completamos todo
          'setup.completedAt': Timestamp.now(),
          'setup.lastStep': 'apps',
          updatedAt: Timestamp.now()
        });

      return { success: true, message: `${apps.length} apps configuradas` };

    } catch (error) {
      console.error('Error guardando apps:', error);
      return { success: false, message: 'Error guardando apps' };
    }
  }

  /**
   * Configurar nivel de protección (y finalizar setup)
   */
  static async setProtectionLevel(
    userId: string,
    level: string
  ): Promise<{ success: boolean; message: string }> {
    try {
      // 1. Guardar la configuración de nivel (aunque sea fija)
      await db
        .collection('users')
        .doc(userId)
        .collection('config')
        .doc('protection')
        .set({
          level: level, // "extreme"
          configuredAt: Timestamp.now()
        }, { merge: true });

      // 2. Marcar el setup principal como COMPLETO
      // (Esta es la parte que evita el bucle)
      await db
        .collection('users')
        .doc(userId)
        .update({
          'setup.protectionConfigured': true, // <-- Marca este paso
          'setup.completed': true,            // <-- ¡Marca todo como completo!
          'setup.lastStep': 'protection',
          'setup.completedAt': Timestamp.now(),
          updatedAt: Timestamp.now()
        });

      return { success: true, message: 'Nivel de protección configurado' };

    } catch (error) {
      console.error('Error configurando protección:', error);
      return { success: false, message: 'Error en configuración' };
    }
  }
  /**
   * Obtener configuración completa del usuario
   */
  static async getUserConfig(userId: string) {
    try {
      const [pinsDoc, appsDoc, userDoc] = await Promise.all([
        db.collection('users').doc(userId).collection('config').doc('pins').get(),
        db.collection('users').doc(userId).collection('config').doc('apps').get(),
        db.collection('users').doc(userId).get()
      ]);

      if (!pinsDoc.exists) {
        return null;
      }

      const pinsData = pinsDoc.data() as any;
      const appsData = appsDoc.exists ? appsDoc.data() as any : { protectedApps: [] };
      const userData = userDoc.data() as any;

      return {
        userId,
        normalPinHash: pinsData.normalPinHash,
        securityPinHash: pinsData.securityPinHash,
        protectedApps: appsData.protectedApps || [],
        setupCompleted: userData.setup?.completed || false,
        permissionsGranted: userData.setup?.permissionsGranted || false,
        emergencyContacts: userData.emergencyContacts || [],
        createdAt: pinsData.createdAt,
        lastUpdated: pinsData.lastUpdated
      };

    } catch (error) {
      console.error('Error obteniendo configuración:', error);
      return null;
    }
  }

  /**
   * Registrar desbloqueo exitoso
   */
  private static async logUnlock(userId: string, mode: 'normal' | 'security'): Promise<void> {
    try {
      await db
        .collection('users')
        .doc(userId)
        .collection('unlock_history')
        .add({
          mode,
          timestamp: Timestamp.now(),
          success: true
        });

      const increment = FieldValue.increment(1);
      const updateData: any = {
        'stats.totalUnlocks': increment,
        'stats.lastUnlock': Timestamp.now()
      };
      
      if (mode === 'normal') {
        updateData['stats.normalUnlocks'] = increment;
      } else {
        updateData['stats.securityUnlocks'] = increment;
      }
      
      await db.collection('users').doc(userId).update(updateData);

    } catch (error) {
      console.error('Error logging unlock:', error);
    }
  }

  /**
   * Registrar intento fallido
   */
  private static async logFailedAttempt(userId: string, pinLength: number): Promise<void> {
    try {
      await db
        .collection('users')
        .doc(userId)
        .collection('failed_attempts')
        .add({
          timestamp: Timestamp.now(),
          pinLength
        });

      await db
        .collection('users')
        .doc(userId)
        .update({
          'stats.failedAttempts': FieldValue.increment(1)
        });

    } catch (error) {
      console.error('Error logging failed attempt:', error);
    }
  }
}

export default ConfigService;