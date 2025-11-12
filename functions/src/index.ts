import * as functions from 'firebase-functions';
import AlertsService from './service/alerts';
import ConfigService from './service/config';
import UsersService from './service/users';
import AuthService from './service/auth';

// ============================================
// AUTH ENDPOINTS
// ============================================
export const registerUser = functions.https.onCall(async (data, context) => {
    const { email, password, displayName } = data;
    try {
        return await AuthService.registerUser(email, password, displayName);
    } catch (error: any) {
        return { success: false, message: error.message };
    }
});

// ============================================
// CONFIG ENDPOINTS (Setup inicial)
// ============================================
export const savePins = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');
    
    const { normalPin, securityPin } = data;
    return await ConfigService.savePins(uid, normalPin, securityPin);
});

export const saveProtectedApps = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');
    
    const { apps } = data;
    return await ConfigService.saveProtectedApps(uid, apps);
});

export const verifyPin = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');
    
    const { pin } = data;
    return await ConfigService.verifyPin(uid, pin);
});

// ============================================
// SECURITY EVENTS (Lo nuevo - Sensores)
// ============================================

/**
 * ENDPOINT CRÍTICO: Se llama cuando hay movimiento anormal
 * (Acelerómetro > threshold)
 */
export const reportAbnormalMovement = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    const { latitude, longitude, accelerationValue } = data;

    console.log(`🚨 Movimiento anormal reportado por ${uid}`);
    console.log(`   Aceleración: ${accelerationValue}m/s²`);
    console.log(`   Ubicación: ${latitude}, ${longitude}`);

    // Activar modo seguridad
    return await AlertsService.activateSecurityMode(
        uid,
        'abrupt_movement',
        {
            latitude,
            longitude,
            accelerationValue,
            timestamp: Date.now()
        }
    );
});

/**
 * ENDPOINT CRÍTICO: Se llama cuando hay velocidad imposible
 * (GPS > 100m en 5 segundos)
 */
export const reportSuspiciousSpeed = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    const { latitude, longitude, calculatedSpeed } = data;

    console.log(`🚨 Velocidad imposible reportada por ${uid}`);
    console.log(`   Velocidad: ${calculatedSpeed}m/s`);
    console.log(`   Ubicación: ${latitude}, ${longitude}`);

    // Activar modo seguridad
    return await AlertsService.activateSecurityMode(
        uid,
        'suspicious_speed',
        {
            latitude,
            longitude,
            calculatedSpeed,
            timestamp: Date.now()
        }
    );
});

/**
 * ENDPOINT: Botón de pánico presionado
 */
export const triggerPanicButton = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    const { latitude, longitude } = data;

    console.log(`🚨 BOTÓN DE PÁNICO PRESIONADO por ${uid}`);

    return await AlertsService.activateSecurityMode(
        uid,
        'panic_button',
        {
            latitude,
            longitude,
            timestamp: Date.now()
        }
    );
});

// ============================================
// ALERTS ENDPOINTS (Control remoto)
// ============================================

/**
 * Bloquear dispositivo remotamente
 */
export const lockDeviceRemotely = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    const { alertId } = data;
    return await AlertsService.remoteLockDevice(uid, alertId);
});

/**
 * Borrar datos del dispositivo
 */
export const wipeDeviceRemotely = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    const { alertId } = data;
    return await AlertsService.remoteWipeData(uid, alertId);
});

/**
 * Desactivar modo seguridad (Falsa alarma)
 */
export const deactivateSecurityMode = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    const { alertId } = data;
    return await AlertsService.deactivateSecurityMode(uid, alertId);
});

/**
 * Obtener historial de alertas
 */
export const getSecurityAlerts = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    return await UsersService.getSecurityAlerts(uid);
});

// ============================================
// USERS ENDPOINTS
// ============================================

export const getSetupStatus = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    return await UsersService.getSetupStatus(uid);
});

export const updateUserProfile = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    return await UsersService.updateUserProfile(uid, data);
});

export const getActivityFeed = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    return await UsersService.getActivityFeed(uid);
});

// ============================================
// CONFIG ENDPOINTS
// ============================================

export const setProtectionLevel = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    const { level } = data;
    return await ConfigService.setProtectionLevel(uid, level || 'extreme');
});

export const getUserConfig = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) throw new Error('No autenticado');

    return await ConfigService.getUserConfig(uid);
});