import * as admin from 'firebase-admin';

// Inicializar Firebase Admin SDK SOLO SI no se ha hecho antes.
// Esto evita errores durante las pruebas o en entornos de emulación.
if (!admin.apps.length) {
  admin.initializeApp();
}

/**
 * Instancia de Firestore Database.
 * Impórtala en todos los servicios que necesiten interactuar con la base de datos.
 */
export const db = admin.firestore();

/**
 * Instancia de Firebase Authentication.
 * Impórtala en todos los servicios que necesiten manejar usuarios de Auth.
 */
export const auth = admin.auth();