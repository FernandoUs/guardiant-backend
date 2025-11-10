import { db} from './firestore';
import * as bcrypt from 'bcryptjs';
// Importamos Timestamp y FieldValue directamente de la librería de admin
import { Timestamp, FieldValue } from 'firebase-admin/firestore';

// Interfaces
interface PinConfiguration {
  normalPinHash: string;
  securityPinHash: string;
  createdAt: Timestamp;
  lastUpdated: Timestamp;
}

interface AppConfiguration {
  packageName: string;
  appName: string;
  icon?: string | null; // Aceptamos null también
  isProtected: boolean;
  addedAt: Timestamp;
}

interface UserConfiguration {
  userId: string;
  normalPinHash: string;
  securityPinHash: string;
  protectionLevel: 'basic' | 'camouflage' | 'extreme';
  protectedApps: AppConfiguration[];
  setupCompleted: boolean;
  permissionsGranted: boolean;
  emergencyContacts: string[];
  createdAt: Timestamp;
  lastUpdated: Timestamp;
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
        return {
          success: false,
          message: 'Ambos PINs son requeridos'
        };
      }
      if (normalPin.length < 4 || normalPin.length > 6) {
        return {
          success: false,
          message: 'El PIN debe tener entre 4 y 6 dígitos'
        };
      }
      if (normalPin === securityPin) {
        return {
          success: false,
          message: 'Los PINs deben ser diferentes'
        };
      }
      if (!/^\d+$/.test(normalPin) || !/^\d+$/.test(securityPin)) {
        return {
          success: false,
          message: 'Los PINs solo deben contener números'
        };
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
        });

      // Actualizar usuario principal
      await db
        .collection('users')
        .doc(userId)
        .update({
          'setup.pinsConfigured': true,
          'setup.lastStep': 'pins',
          updatedAt: Timestamp.now()
        });

      return {
        success: true,
        message: 'PINs guardados exitosamente'
      };

    } catch (error) {
      console.error('Error guardando PINs:', error);
      return {
        success: false,
        message: 'Error guardando configuración'
      };
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
        return {
          success: false,
          mode: null,
          message: 'Configuración no encontrada'
        };
      }

      const { normalPinHash, securityPinHash } = pinsDoc.data() as PinConfiguration;

      // Verificar PIN normal
      const isNormalPin = await bcrypt.compare(pin, normalPinHash);
      if (isNormalPin) {
        await this.logUnlock(userId, 'normal');
        
        return {
          success: true,
          mode: 'normal',
          message: 'PIN normal correcto'
        };
      }

      // Verificar PIN de seguridad
      const isSecurityPin = await bcrypt.compare(pin, securityPinHash);
      if (isSecurityPin) {
        await this.activateSecurityMode(userId);
        
        return {
          success: true,
          mode: 'security',
          message: 'PIN de seguridad correcto - Modo camuflaje activado'
        };
      }

      // PIN incorrecto
      await this.logFailedAttempt(userId, pin.length);
      
      return {
        success: false,
        mode: null,
        message: 'PIN incorrecto'
      };

    } catch (error) {
      console.error('Error verificando PIN:', error);
      return {
        success: false,
        mode: null,
        message: 'Error en verificación'
      };
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
        // =======================================================
        // SOLUCIÓN: Si app.icon es undefined, guardamos null
        icon: app.icon || null, 
        // =======================================================
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

      // Actualizar progreso de setup
      await db
        .collection('users')
        .doc(userId)
        .update({
          'setup.appsConfigured': true,
          'setup.lastStep': 'apps',
          updatedAt: Timestamp.now()
        });

      return {
        success: true,
        message: `${apps.length} apps configuradas`
      };

    } catch (error) {
      console.error('Error guardando apps:', error);
      return {
        success: false,
        message: 'Error guardando apps'
      };
    }
  }

  /**
   * Configurar nivel de protección
   */
  static async setProtectionLevel(
    userId: string,
    level: 'basic' | 'camouflage' | 'extreme'
  ): Promise<{ success: boolean; message: string }> {
    try {
      await db
        .collection('users')
        .doc(userId)
        .collection('config')
        .doc('protection')
        .set({
          level,
          features: this.getProtectionFeatures(level),
          configuredAt: Timestamp.now()
        });

      // Marcar setup como completo
      await db
        .collection('users')
        .doc(userId)
        .update({
          'setup.protectionConfigured': true,
          'setup.completed': true,
          'setup.lastStep': 'protection',
          'setup.completedAt': Timestamp.now(),
          updatedAt: Timestamp.now()
        });

      return {
        success: true,
        message: 'Nivel de protección configurado'
      };

    } catch (error) {
      console.error('Error configurando protección:', error);
      return {
        success: false,
        message: 'Error en configuración'
      };
    }
  }
  
  /**
   * Obtener configuración completa del usuario
   */
  static async getUserConfig(userId: string): Promise<UserConfiguration | null> {
    try {
      const [pinsDoc, appsDoc, protectionDoc] = await Promise.all([
        db.collection('users').doc(userId).collection('config').doc('pins').get(),
        db.collection('users').doc(userId).collection('config').doc('apps').get(),
        db.collection('users').doc(userId).collection('config').doc('protection').get()
      ]);

      if (!pinsDoc.exists) {
        return null;
      }

      const pinsData = pinsDoc.data() as any;
      const appsData = appsDoc.exists ? appsDoc.data() as any : { protectedApps: [] };
      const protectionData = protectionDoc.exists ? protectionDoc.data() as any : { level: 'basic' };

      // Idealmente, también deberíamos traer el documento 'users' principal
      // para obtener setupCompleted, permissionsGranted, y emergencyContacts.
      // Por ahora, los dejamos como valores fijos/vacíos.
      
      return {
        userId,
        normalPinHash: pinsData.normalPinHash,
        securityPinHash: pinsData.securityPinHash,
        protectionLevel: protectionData.level,
        protectedApps: appsData.protectedApps || [],
        setupCompleted: true, 
        permissionsGranted: false, 
        emergencyContacts: [], 
        createdAt: pinsData.createdAt,
        lastUpdated: pinsData.lastUpdated
      };

    } catch (error) {
      console.error('Error obteniendo configuración:', error);
      return null;
    }
  }

  /**
   * Activar modo seguridad (cuando se usa PIN de seguridad)
   */
  private static async activateSecurityMode(userId: string): Promise<void> {
    try {
      // Crear alerta de seguridad
      await db
        .collection('users')
        .doc(userId)
        .collection('security_alerts')
        .add({
          type: 'security_pin_used',
          timestamp: Timestamp.now(),
          status: 'active',
          resolved: false
        });

      // Actualizar estado del usuario
      await db
        .collection('users')
        .doc(userId)
        .update({
          currentMode: 'security',
          'security.modeActivatedAt': Timestamp.now(),
          'security.alertActive': true
        });

    } catch (error) {
      console.error('Error activando modo seguridad:', error);
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

      // Incrementar contador
      await db
        .collection('users')
        .doc(userId)
        .update({
          // Usamos FieldValue importado
          'stats.totalUnlocks': FieldValue.increment(1),
          'stats.lastUnlock': Timestamp.now()
        });

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

  /**
   * Obtener features según nivel de protección
   */
  private static getProtectionFeatures(level: string): string[] {
    const features: Record<string, string[]> = {
      basic: [
        'block_apps',
        'pin_protection'
      ],
      camouflage: [
        'block_apps',
        'pin_protection',
        'close_sessions',
        'hide_apps',
        'capture_evidence',
        'gps_tracking',
        'send_alerts'
      ],
      extreme: [
        'block_apps',
        'pin_protection',
        'close_sessions',
        'hide_apps',
        'capture_evidence',
        'gps_tracking',
        'send_alerts',
        'delete_sensitive_data',
        'remote_wipe'
      ]
    };

    return features[level] || features.basic;
  }
}

export default ConfigService;