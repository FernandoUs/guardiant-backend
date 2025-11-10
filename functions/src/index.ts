import * as functions from 'firebase-functions';
// Importamos los servicios
import AuthService from './service/auth';
import ConfigService from './service/config';
import UsersService from './service/users';

// Importamos la instancia centralizada de firestore
import { db } from './service/firestore';
import * as admin from 'firebase-admin'; // Aún lo necesitamos para Timestamp y FieldValue

// ============================================
// AUTHENTICATION TRIGGERS
// ============================================

/**
 * Trigger: Crear documento de usuario al registrarse
 * (Esta lógica se queda aquí, está perfecta)
 */
export const onUserCreate = functions.auth.user().onCreate(async (user) => {
  try {
    await db.collection('users').doc(user.uid).set({ // <-- Usa 'db' importado
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
 * (Esta lógica se queda aquí, está perfecta)
 */
export const onUserDelete = functions.auth.user().onDelete(async (user) => {
  try {
    const batch = db.batch(); // <-- Usa 'db' importado

    // Eliminar documento principal
    batch.delete(db.collection('users').doc(user.uid));

    // Eliminar subcolecciones (como lo tenías)
    const collections = ['config', 'security_alerts', 'unlock_history', 'failed_attempts'];
    for (const collectionName of collections) {
      const snapshot = await db
        .collection('users')
        .doc(user.uid)
        .collection(collectionName)
        .get();
      snapshot.docs.forEach(doc => {
        batch.delete(doc.ref);
      });
    }

    await batch.commit();
    console.log('✅ Datos de usuario eliminados:', user.uid);
  } catch (error) {
    console.error('❌ Error eliminando datos de usuario:', error);
  }
});

// ============================================
// AUTHENTICATION APIs (NUEVO)
// ============================================

/**
 * API: Registrar un nuevo usuario
 * POST /registerUser
 * Body: { email: string, password: string, displayName?: string }
 */
export const registerUser = functions.https.onCall(async (data, context) => {
  // Validación simple de datos
  const { email, password, displayName } = data;
  if (!email || !password) {
    throw new functions.https.HttpsError(
      'invalid-argument',
      'Email y contraseña son requeridos.'
    );
  }

  try {
    // Llama al servicio de autenticación
    const result = await AuthService.registerUser(email, password, displayName);
    return result;
  } catch (error: any) {
    console.error('❌ Error en registerUser (index):', error);
    // AuthService ya lanza un HttpsError, así que solo lo re-lanzamos
    throw error;
  }
});

/**
 * API: Enviar email de reseteo de contraseña
 * POST /sendPasswordResetEmail
 * Body: { email: string }
 */
export const sendPasswordResetEmail = functions.https.onCall(async (data, context) => {
  const { email } = data;
  if (!email) {
    throw new functions.https.HttpsError(
      'invalid-argument',
      'El email es requerido.'
    );
  }

  
});


// ============================================
// CONFIGURATION APIs (REFACTORIZADAS)
// ============================================

// Función helper para validar autenticación
function checkAuth(context: functions.https.CallableContext) {
  if (!context.auth) {
    throw new functions.https.HttpsError(
      'unauthenticated',
      'Usuario no autenticado'
    );
  }
  return context.auth.uid;
}

/**
 * API: Guardar PINs (Normal y Seguridad)
 * POST /savePins
 * Body: { normalPin: string, securityPin: string }
 */
export const savePins = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { normalPin, securityPin } = data;

  if (!normalPin || !securityPin) {
    throw new functions.https.HttpsError('invalid-argument', 'Ambos PINs son requeridos');
  }

  try {
    // Llama al servicio de configuración
    const result = await ConfigService.savePins(userId, normalPin, securityPin);
    if (!result.success) {
      throw new functions.https.HttpsError('invalid-argument', result.message);
    }
    return result;
  } catch (error: any) {
    console.error('❌ Error en savePins (index):', error);
    throw new functions.https.HttpsError('internal', error.message);
  }
});

/**
 * API: Verificar PIN (para desbloqueo)
 * POST /verifyPin
 * Body: { pin: string }
 */
export const verifyPin = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { pin } = data;

  if (!pin) {
    throw new functions.https.HttpsError('invalid-argument', 'PIN es requerido');
  }

  try {
    // Llama al servicio de configuración
    const result = await ConfigService.verifyPin(userId, pin);
    return result;
  } catch (error: any) {
    console.error('❌ Error en verifyPin (index):', error);
    throw new functions.https.HttpsError('internal', error.message);
  }
});

/**
 * API: Guardar apps protegidas
 * POST /saveProtectedApps
 * Body: { apps: Array<{ packageName, appName, icon? }> }
 */
export const saveProtectedApps = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { apps } = data;

  if (!Array.isArray(apps) || apps.length === 0) {
    throw new functions.https.HttpsError('invalid-argument', 'Apps debe ser un array no vacío');
  }
  
  // (Validación de estructura interna de apps movida al servicio o asumida correcta)
  
  try {
    // Llama al servicio de configuración
    const result = await ConfigService.saveProtectedApps(userId, apps);
    if (!result.success) {
      throw new functions.https.HttpsError('internal', result.message);
    }
    return result;
  } catch (error: any) {
    console.error('❌ Error en saveProtectedApps (index):', error);
    throw new functions.https.HttpsError('internal', error.message);
  }
});

/**
 * API: Configurar nivel de protección
 * POST /setProtectionLevel
 * Body: { level: 'basic' | 'camouflage' | 'extreme' }
 */
export const setProtectionLevel = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { level } = data;

  const validLevels = ['basic', 'camouflage', 'extreme'];
  if (!validLevels.includes(level)) {
    throw new functions.https.HttpsError('invalid-argument', 'Nivel de protección inválido.');
  }

  try {
    // Llama al servicio de configuración
    const result = await ConfigService.setProtectionLevel(userId, level);
    if (!result.success) {
      throw new functions.https.HttpsError('internal', result.message);
    }
    return result;
  } catch (error: any) {
    console.error('❌ Error en setProtectionLevel (index):', error);
    throw new functions.https.HttpsError('internal', error.message);
  }
});

/**
 * API: Obtener configuración del usuario
 * GET /getUserConfig
 */
export const getUserConfig = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);

  try {
    // Llama al servicio de configuración
    const config = await ConfigService.getUserConfig(userId);
    if (!config) {
      throw new functions.https.HttpsError('not-found', 'Configuración no encontrada.');
    }

    // No enviar hashes de PINs al cliente
    const { normalPinHash, securityPinHash, ...safeConfig } = config;
    return { success: true, data: safeConfig };
    
  } catch (error: any) {
    console.error('❌ Error en getUserConfig (index):', error);
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError('internal', error.message);
  }
});

/**
 * API: Cambiar PINs
 * POST /changePins
 * Body: { currentPin, newNormalPin, newSecurityPin }
 */
export const changePins = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);
  const { currentPin, newNormalPin, newSecurityPin } = data;

  if (!currentPin || !newNormalPin || !newSecurityPin) {
    throw new functions.https.HttpsError('invalid-argument', 'Todos los PINs son requeridos');
  }

  try {
    // 1. Verificar PIN actual (usando ConfigService)
    const verifyResult = await ConfigService.verifyPin(userId, currentPin);
    if (!verifyResult.success) {
      throw new functions.https.HttpsError('permission-denied', 'PIN actual incorrecto');
    }

    // 2. Guardar nuevos PINs (usando ConfigService)
    const result = await ConfigService.savePins(userId, newNormalPin, newSecurityPin);
    if (!result.success) {
      throw new functions.https.HttpsError('invalid-argument', result.message);
    }
    return { success: true, message: 'PINs actualizados correctamente' };

  } catch (error: any) {
    console.error('❌ Error en changePins (index):', error);
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError('internal', error.message);
  }
});


// ============================================
// USER PROFILE APIs (REFACTORIZADAS)
// ============================================

/**
 * API: Obtener estado del setup
 * GET /getSetupStatus
 */
export const getSetupStatus = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);

  try {
    // Llama al servicio de usuario
    const result = await UsersService.getSetupStatus(userId);
    return { success: true, data: result };
  } catch (error: any) {
    console.error('❌ Error en getSetupStatus (index):', error);
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError('internal', error.message);
  }
});

/**
 * API: Actualizar perfil de usuario
 * POST /updateUserProfile
 * Body: { displayName?, phoneNumber?, emergencyContacts? }
 */
export const updateUserProfile = functions.https.onCall(async (data, context) => {
  const userId = checkAuth(context);

  // 'data' contiene todo el body (displayName, phoneNumber, etc.)
  try {
    // Llama al servicio de usuario
    const result = await UsersService.updateUserProfile(userId, data);
    return result;
  } catch (error: any) {
    console.error('❌ Error en updateUserProfile (index):', error);
    if (error instanceof functions.https.HttpsError) throw error;
    throw new functions.https.HttpsError('internal', error.message);
  }
});


// ============================================
// HELPER/UTILITY APIs
// ============================================
/**
 * API: Health Check
 * (Se queda igual)
 */
export const healthCheck = functions.https.onRequest((req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'guardiant-backend',
    version: '1.0.0'
  });
});