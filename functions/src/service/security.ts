import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';

// 1. REPORTAR EVENTO DE SEGURIDAD
export const reportSecurityEvent = functions.https.onCall(async (data, context) => {
    const { userId, eventType, latitude, longitude, timestamp } = data;
    const uid = context.auth?.uid;

    if (!uid) return { success: false, message: 'No autorizado' };

    // Guardar en Firestore
    const eventRef = await admin.firestore().collection('security_events').add({
        userId: uid,
        eventType, // "ABNORMAL_MOVEMENT", "COERCION", "SUSPICIOUS_SPEED"
        latitude,
        longitude,
        timestamp,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Si es CRÍTICO, notificar inmediatamente
    if (['ABNORMAL_MOVEMENT', 'SUSPICIOUS_SPEED', 'COERCION'].includes(eventType)) {
        await notifyEmergencyContacts(uid, eventType, latitude, longitude);
    }

    return { 
        success: true, 
        message: 'Evento registrado',
        eventId: eventRef.id 
    };
});

// 2. OBTENER HISTORIAL DE EVENTOS
export const getSecurityEvents = functions.https.onCall(async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) return { success: false, message: 'No autorizado' };

    const events = await admin.firestore()
        .collection('security_events')
        .where('userId', '==', uid)
        .orderBy('timestamp', 'desc')
        .limit(50)
        .get();

    return {
        success: true,
        events: events.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }))
    };
});

// 3. BLOQUEO REMOTO (Enviar comando por FCM)
export const blockDeviceRemotely = functions.https.onCall(async (data, context) => {
    const { userId, reason } = data;
    const uid = context.auth?.uid;

    if (!uid) return { success: false, message: 'No autorizado' };

    // Obtener FCM token del usuario
    const userDoc = await admin.firestore().collection('users').doc(userId).get();
    const fcmToken = userDoc.data()?.fcmToken;

    if (!fcmToken) {
        return { success: false, message: 'Dispositivo no encontrado' };
    }

    // Enviar comando BLOCK por FCM
    await admin.messaging().send({
        token: fcmToken,
        data: {
            command: 'BLOCK',
            reason,
            timestamp: Date.now().toString(),
        },
    });

    // Registrar
    await admin.firestore().collection('security_events').add({
        userId,
        eventType: 'REMOTE_BLOCK',
        reason,
        timestamp: Date.now(),
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { success: true, message: 'Dispositivo bloqueado remotamente' };
});

// 4. AUXILIAR: Notificar contactos de emergencia
async function notifyEmergencyContacts(
    userId: string,
    eventType: string,
    latitude: number,
    longitude: number
) {
    const userDoc = await admin.firestore().collection('users').doc(userId).get();
    const emergencyContacts = userDoc.data()?.emergencyContacts || [];

    for (const contact of emergencyContacts) {
        // TODO: Integrar con Twilio/SMS
        console.log(`📱 SMS a ${contact.phone}: ⚠️ EVENTO ${eventType} en ${latitude},${longitude}`);
    }

    return true;
}