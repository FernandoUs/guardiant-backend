import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import AlertsService from './service/alerts';
import ConfigService from './service/config';
import UsersService from './service/users';
import AuthService from './service/auth';
import { HttpsError } from 'firebase-functions/v1/https';
import { SmsService } from './service/sms';

// ============================================
// HELPER: Validar autenticación
// ============================================
const checkAuth = (context: functions.https.CallableContext): string => {
  if (!context.auth) {
    throw new HttpsError('unauthenticated', 'Usuario no autenticado');
  }
  return context.auth.uid;
};

// ============================================
// AUTHENTICATION TRIGGERS
// ============================================

/**
 * Trigger: Crear documento de usuario al registrarse
 */
export const onUserCreate = functions.auth.user().onCreate(async (user) => {
  try {
    await admin.firestore().collection('users').doc(user.uid).set({
      email: user.email,
      displayName: user.displayName || null,
      photoURL: user.photoURL || null,
      phoneNumber: user.phoneNumber || null,
      createdAt: admin.firestore.Timestamp.now(),
      updatedAt: admin.firestore.Timestamp.now(),
      
      setup: {
        completed: false,
        pinsConfigured: false,
        appsConfigured: false,
        permissionsGranted: false,
        lastStep: null,
        startedAt: admin.firestore.Timestamp.now(),
        completedAt: null
      },
      
      stats: {
        totalUnlocks: 0,
        failedAttempts: 0,
        lastUnlock: null,
        normalUnlocks: 0,
        securityUnlocks: 0
      },
      
      currentMode: 'normal',
      security: {
        alertActive: false,
        modeActivatedAt: null,
        lastSecurityPinUse: null
      },
      
      fcmToken: null,
      status: 'active',
      emailVerified: user.emailVerified
    });

    console.log('✅ Usuario creado en Firestore:', user.uid);
  } catch (error) {
    console.error('❌ Error creando documento de usuario:', error);
  }
});

/**
 * Trigger: Limpiar datos cuando se elimina un usuario
 */
export const onUserDelete = functions.auth.user().onDelete(async (user) => {
  try {
    const db = admin.firestore();
    const batch = db.batch();
    batch.delete(db.collection('users').doc(user.uid));
    
    await batch.commit();
    console.log('✅ Documento de usuario eliminado:', user.uid);
  } catch (error) {
    console.error('❌ Error eliminando datos de usuario:', error);
  }
});

// ============================================
// AUTH ENDPOINTS
// ============================================

/**
 * API: Registrar usuario
 */
export const registerUser = functions.https.onCall(async (data, context) => {
    const { email, password, displayName } = data;
    if (!email || !password) {
        throw new HttpsError('invalid-argument', 'Email y contraseña son requeridos');
    }
    try {
        return await AuthService.registerUser(email, password, displayName);
    } catch (error: any) {
        throw error;
    }
});

// ============================================
// CONFIG ENDPOINTS (Setup inicial)
// ============================================

/**
 * API: Guardar PINs (Normal y Seguridad)
 */
export const savePins = functions.https.onCall(async (data, context) => {
    const userId = checkAuth(context);
    const { normalPin, securityPin } = data;
    if (!normalPin || !securityPin) {
        throw new HttpsError('invalid-argument', 'Ambos PINs son requeridos');
    }
    try {
        return await ConfigService.savePins(userId, normalPin, securityPin);
    } catch (error: any) {
        console.error('❌ Error en savePins:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Verificar PIN (para desbloqueo)
 */
export const verifyPin = functions.https.onCall(async (data, context) => {
    const userId = checkAuth(context);
    const { pin } = data;
    if (!pin) {
        throw new HttpsError('invalid-argument', 'PIN es requerido');
    }
    try {
        return await ConfigService.verifyPin(userId, pin);
    } catch (error: any) {
        console.error('❌ Error en verifyPin:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Guardar apps protegidas
 */
export const saveProtectedApps = functions.https.onCall(async (data, context) => {
    const userId = checkAuth(context);
    const { apps } = data;
    if (!Array.isArray(apps) || apps.length === 0) {
        throw new HttpsError('invalid-argument', 'Apps debe ser un array con al menos 1 app');
    }
    try {
        return await ConfigService.saveProtectedApps(userId, apps);
    } catch (error: any) {
        console.error('❌ Error en saveProtectedApps:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Finalizar setup y fijar nivel de protección
 */
export const setProtectionLevel = functions.https.onCall(async (data, context) => {
    const userId = checkAuth(context);
    const fixedLevel = "extreme";
    
    try {
        return await ConfigService.setProtectionLevel(userId, fixedLevel);
    } catch (error: any) {
        console.error('❌ Error en setProtectionLevel:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Obtener configuración del usuario
 */
export const getUserConfig = functions.https.onCall(async (data, context) => {
    const userId = checkAuth(context);
    try {
        const config = await ConfigService.getUserConfig(userId);
        if (!config) {
            throw new HttpsError('not-found', 'Configuración no encontrada.');
        }
        // No enviar los hashes de PINs al cliente
        const { normalPinHash, securityPinHash, ...safeConfig } = config;
        return { success: true, data: safeConfig };
    } catch (error: any) {
        console.error('❌ Error en getUserConfig:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Cambiar PINs
 */
export const changePins = functions.https.onCall(async (data, context) => {
    const userId = checkAuth(context);
    const { currentPin, newNormalPin, newSecurityPin } = data;
    if (!currentPin || !newNormalPin || !newSecurityPin) {
        throw new HttpsError('invalid-argument', 'Todos los PINs son requeridos');
    }
    try {
        const verifyResult = await ConfigService.verifyPin(userId, currentPin);
        if (!verifyResult.success) {
            throw new HttpsError('permission-denied', 'PIN actual incorrecto');
        }
        return await ConfigService.savePins(userId, newNormalPin, newSecurityPin);
    } catch (error: any) {
        console.error('❌ Error en changePins:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

// ============================================
// SECURITY EVENTS (Lo nuevo - Sensores)
// ============================================

/**
 * ENDPOINT CRÍTICO: Se llama cuando hay movimiento anormal
 * (Acelerómetro > threshold)
 */
export const reportAbnormalMovement = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { latitude, longitude, accelerationValue } = data;

    if (accelerationValue === undefined) {
        throw new HttpsError('invalid-argument', 'accelerationValue es requerido');
    }

    try {
        console.log(`🚨 Movimiento anormal reportado por ${uid}`);
        console.log(`   Aceleración: ${accelerationValue}m/s²`);
        console.log(`   Ubicación: ${latitude}, ${longitude}`);

        return await AlertsService.activateSecurityMode(
            uid,
            'abrupt_movement',
            {
                latitude: latitude || null,
                longitude: longitude || null,
                accelerationValue,
                timestamp: Date.now()
            }
        );
    } catch (error: any) {
        console.error('❌ Error en reportAbnormalMovement:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * ENDPOINT CRÍTICO: Se llama cuando hay velocidad imposible
 * (GPS > 100m en 5 segundos)
 */
export const reportSuspiciousSpeed = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { latitude, longitude, calculatedSpeed, distance, timeDiff } = data;

    if (calculatedSpeed === undefined) {
        throw new HttpsError('invalid-argument', 'calculatedSpeed es requerido');
    }

    try {
        console.log(`🚨 Velocidad imposible reportada por ${uid}`);
        console.log(`   Velocidad: ${calculatedSpeed}m/s`);
        console.log(`   Ubicación: ${latitude}, ${longitude}`);

        return await AlertsService.activateSecurityMode(
            uid,
            'suspicious_speed',
            {
                latitude: latitude || null,
                longitude: longitude || null,
                calculatedSpeed,
                distance: distance || null,
                timeDiff: timeDiff || null,
                timestamp: Date.now()
            }
        );
    } catch (error: any) {
        console.error('❌ Error en reportSuspiciousSpeed:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * ENDPOINT: Botón de pánico presionado
 */
export const triggerPanicButton = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { latitude, longitude, reason } = data;

    try {
        console.log(`🚨🚨🚨 BOTÓN DE PÁNICO PRESIONADO por ${uid}`);
        console.log(`   Razón: ${reason || 'No especificada'}`);

        return await AlertsService.activateSecurityMode(
            uid,
            'panic_button',
            {
                latitude: latitude || null,
                longitude: longitude || null,
                reason: reason || 'Usuario presionó botón de pánico',
                timestamp: Date.now(),
                priority: 'CRITICAL'
            }
        );
    } catch (error: any) {
        console.error('❌ Error en triggerPanicButton:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

// ============================================
// ALERTS ENDPOINTS (Control remoto)
// ============================================

/**
 * Bloquear dispositivo remotamente
 */
export const lockDeviceRemotely = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { alertId } = data;
    if (!alertId) {
        throw new HttpsError('invalid-argument', 'alertId es requerido');
    }
    try {
        return await AlertsService.remoteLockDevice(uid, alertId);
    } catch (error: any) {
        console.error('❌ Error en lockDeviceRemotely:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * Borrar datos del dispositivo
 */
export const wipeDeviceRemotely = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { alertId } = data;
    if (!alertId) {
        throw new HttpsError('invalid-argument', 'alertId es requerido');
    }
    try {
        return await AlertsService.remoteWipeData(uid, alertId);
    } catch (error: any) {
        console.error('❌ Error en wipeDeviceRemotely:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * Desactivar modo seguridad (Falsa alarma)
 */
export const deactivateSecurityMode = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { alertId } = data;
    if (!alertId) {
        throw new HttpsError('invalid-argument', 'alertId es requerido');
    }
    try {
        return await AlertsService.deactivateSecurityMode(uid, alertId);
    } catch (error: any) {
        console.error('❌ Error en deactivateSecurityMode:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * Actualizar FCM Token (llamado desde la app móvil)
 */
export const updateFCMToken = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { token } = data;
    if (!token) {
        throw new HttpsError('invalid-argument', 'FCM token es requerido');
    }
    try {
        await admin.firestore().collection('users').doc(uid).update({
            fcmToken: token,
            fcmTokenUpdatedAt: admin.firestore.Timestamp.now()
        });
        return { success: true, message: 'FCM token actualizado' };
    } catch (error: any) {
        console.error('❌ Error en updateFCMToken:', error);
        throw new HttpsError('internal', error.message);
    }
});

// ============================================
// USERS ENDPOINTS
// ============================================

/**
 * API: Obtener estado del setup
 */
export const getSetupStatus = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    try {
        return await UsersService.getSetupStatus(uid);
    } catch (error: any) {
        console.error('❌ Error en getSetupStatus:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Actualizar perfil de usuario
 */
export const updateUserProfile = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    try {
        return await UsersService.updateUserProfile(uid, data);
    } catch (error: any) {
        console.error('❌ Error en updateUserProfile:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Obtener feed de actividad (desbloqueos, intentos)
 */
export const getActivityFeed = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    try {
        return await UsersService.getActivityFeed(uid);
    } catch (error: any) {
        console.error('❌ Error en getActivityFeed:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Obtener alertas de seguridad
 */
export const getSecurityAlerts = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    try {
        return await UsersService.getSecurityAlerts(uid);
    } catch (error: any) {
        console.error('❌ Error en getSecurityAlerts:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

/**
 * API: Registrar un evento de seguridad genérico
 */
export const logSecurityEvent = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { eventType, details } = data;
    if (!eventType) {
        throw new HttpsError('invalid-argument', 'eventType es requerido');
    }
    try {
        return await UsersService.logSecurityEvent(uid, eventType, details);
    } catch (error: any) {
        console.error('❌ Error en logSecurityEvent:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

// ============================================
// UTILITY
// ============================================

/**
 * Health Check
 */
export const healthCheck = functions.https.onRequest((req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        service: 'guardiant-backend',
        version: '1.0.0'
    });
});

export const deactivateAlertOnUnlock = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { alertId } = data;
    
    if (!alertId) {
        throw new HttpsError('invalid-argument', 'alertId es requerido');
    }
    
    try {
        return await AlertsService.deactivateAlertOnUnlock(uid, alertId);
    } catch (error: any) {
        console.error('❌ Error en deactivateAlertOnUnlock:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});

export const sendVerificationSms = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { phoneNumber } = data;

    if (!phoneNumber) {
        throw new HttpsError('invalid-argument', 'phoneNumber es requerido');
    }

    try {
        const code = await SmsService.sendVerificationCode(phoneNumber);

        // Guardar código en Firestore (con expiración de 10 minutos)
        await admin.firestore().collection('verification_codes').doc(uid).set({
            code,
            phoneNumber,
            createdAt: admin.firestore.Timestamp.now(),
            expiresAt: admin.firestore.Timestamp.fromDate(
                new Date(Date.now() + 10 * 60 * 1000) // 10 minutos
            ),
            attempts: 0
        });

        console.log(`✅ Código enviado a ${phoneNumber}`);

        return {
            success: true,
            message: 'Código enviado al teléfono',
            verificationId: uid // Usar el UID como verificación ID
        };

    } catch (error: any) {
        console.error('❌ Error en sendVerificationSms:', error);
        throw new HttpsError('internal', error.message);
    }
});

/**
 * Verificar código SMS
 */
export const verifySmscode = functions.https.onCall(async (data, context) => {
    const uid = checkAuth(context);
    const { code } = data;

    if (!code) {
        throw new HttpsError('invalid-argument', 'code es requerido');
    }

    try {
        const verificationDoc = await admin.firestore()
            .collection('verification_codes')
            .doc(uid)
            .get();

        if (!verificationDoc.exists) {
            throw new HttpsError('not-found', 'No se encontró código de verificación');
        }

        const verificationData = verificationDoc.data() as any;

        // Verificar si expiró
        const expiresAt = verificationData.expiresAt.toDate();
        if (new Date() > expiresAt) {
            throw new HttpsError('invalid-argument', 'El código ha expirado');
        }

        // Verificar intentos (máx 5)
        if (verificationData.attempts >= 5) {
            throw new HttpsError('permission-denied', 'Demasiados intentos fallidos');
        }

        // Verificar código
        if (code !== verificationData.code) {
            // Incrementar intentos
            await verificationDoc.ref.update({
                attempts: verificationData.attempts + 1
            });
            throw new HttpsError('invalid-argument', 'Código incorrecto');
        }

        // ✅ Código correcto - Marcar como verificado
        await admin.firestore().collection('users').doc(uid).update({
            phoneVerified: true,
            phoneNumber: verificationData.phoneNumber,
            verifiedAt: admin.firestore.Timestamp.now()
        });

        // Eliminar código
        await verificationDoc.ref.delete();

        return {
            success: true,
            message: 'Teléfono verificado exitosamente'
        };

    } catch (error: any) {
        console.error('❌ Error en verifySmsCode:', error);
        if (error instanceof HttpsError) throw error;
        throw new HttpsError('internal', error.message);
    }
});