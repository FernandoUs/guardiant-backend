import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';

// Importar servicios
import AuthService from './service/auth';
import ConfigService from './service/config';
import UsersService from './service/users';
import AlertsService from './service/alerts'; // <-- NUEVO SERVICIO
import { HttpsError } from 'firebase-functions/v1/https';

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
      
      // Setup progress
      setup: {
        completed: false,
        pinsConfigured: false,
        appsConfigured: false,
        protectionConfigured: false,
        permissionsGranted: false,
        lastStep: null,
        startedAt: admin.firestore.Timestamp.now(),
        completedAt: null
      },
      
      // Stats
      stats: {
        totalUnlocks: 0,
        failedAttempts: 0,
        lastUnlock: null,
        normalUnlocks: 0,
        securityUnlocks: 0
      },
      
      // Security state
      currentMode: 'normal',
      security: {
        alertActive: false,
        modeActivatedAt: null,
        lastSecurityPinUse: null
      },
      
      // Account status
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
    // NOTA: Las subcolecciones quedan huérfanas. Se necesita una función recursiva.
    await batch.commit();
    console.log('✅ Documento de usuario eliminado:', user.uid);
  } catch (error) {
    console.error('❌ Error eliminando datos de usuario:', error);
  }
});


// ============================================
// AUTHENTICATION APIs
// ============================================

/**
 * API: Registrar usuario (para pruebas)
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
// CONFIGURATION APIs
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
    const result = await ConfigService.savePins(userId, normalPin, securityPin);
    return result;
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
    const result = await ConfigService.saveProtectedApps(userId, apps);
    return result;
  } catch (error: any) {
    console.error('❌ Error en saveProtectedApps:', error);
    if (error instanceof HttpsError) throw error;
    throw new HttpsError('internal', error.message);
  }
});

/**
 * API: Configurar nivel de protección
 */
export const setProtectionLevel = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { level } = data;
  const validLevels = ['basic', 'camouflage', 'extreme'];
  if (!validLevels.includes(level)) {
    throw new HttpsError('invalid-argument', `Nivel de protección inválido.`);
  }
  try {
    const result = await ConfigService.setProtectionLevel(userId, level);
    return result;
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
    const result = await ConfigService.savePins(userId, newNormalPin, newSecurityPin);
    return result;
  } catch (error: any) {
    console.error('❌ Error en changePins:', error);
    if (error instanceof HttpsError) throw error;
    throw new HttpsError('internal', error.message);
  }
});


// ============================================
// USER PROFILE APIs
// ============================================

/**
 * API: Obtener estado del setup
 */
export const getSetupStatus = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  try {
    return await UsersService.getSetupStatus(userId);
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
  const userId = checkAuth(context);
  try {
    return await UsersService.updateUserProfile(userId, data);
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
  const userId = checkAuth(context);
  try {
    return await UsersService.getActivityFeed(userId);
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
  const userId = checkAuth(context);
  try {
    return await UsersService.getSecurityAlerts(userId);
  } catch (error: any) {
    console.error('❌ Error en getSecurityAlerts:', error);
    if (error instanceof HttpsError) throw error;
    throw new HttpsError('internal', error.message);
  }
});

/**
 * API: Registrar un evento de seguridad (ej. fallo de huella, GPS)
 */
export const logSecurityEvent = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { eventType, details } = data;
  if (!eventType) {
    throw new HttpsError('invalid-argument', 'eventType es requerido');
  }
  try {
    return await UsersService.logSecurityEvent(userId, eventType, details);
  } catch (error: any) {
    console.error('❌ Error en logSecurityEvent:', error);
    if (error instanceof HttpsError) throw error;
    throw new HttpsError('internal', error.message);
  }
});


// ============================================
// NUEVOS ENDPOINTS PARA EL PANEL WEB
// ============================================

/**
 * API: Desactivar modo seguridad (Falsa Alarma)
 */
export const deactivateSecurityMode = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context); // El dueño debe estar logueado en el panel web
  const { alertId } = data;
  if (!alertId) {
    throw new HttpsError('invalid-argument', 'alertId es requerido');
  }
  try {
    return await AlertsService.deactivateSecurityMode(userId, alertId);
  } catch (error: any) {
    console.error('❌ Error en deactivateSecurityMode:', error);
    if (error instanceof HttpsError) throw error;
    throw new HttpsError('internal', error.message);
  }
});

/**
 * API: [Marcador] Bloqueo Remoto
 */
export const remoteLockDevice = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { alertId } = data;
  if (!alertId) {
    throw new HttpsError('invalid-argument', 'alertId es requerido');
  }
  try {
    return await AlertsService.remoteLockDevice(userId, alertId);
  } catch (error: any) {
    console.error('❌ Error en remoteLockDevice:', error);
    if (error instanceof HttpsError) throw error;
    throw new HttpsError('internal', error.message);
  }
});

/**
 * API: [Marcador] Borrado Remoto
 */
export const remoteWipeData = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { alertId } = data;
  if (!alertId) {
    throw new HttpsError('invalid-argument', 'alertId es requerido');
  }
  try {
    return await AlertsService.remoteWipeData(userId, alertId);
  } catch (error: any) {
    console.error('❌ Error en remoteWipeData:', error);
    if (error instanceof HttpsError) throw error;
    throw new HttpsError('internal', error.message);
  }
});


// ============================================
// HELPER/UTILITY APIs
// ============================================

/**
 * API: Health Check
 */
export const healthCheck = functions.https.onRequest((req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'guardiant-backend',
    version: '1.0.0'
  });
});