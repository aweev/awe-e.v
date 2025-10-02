import { sendNotification } from './notifications/send';
import { notificationDelivery } from './notifications/delivery';
import { userRegistered } from './auth/user-registered';
import { dailyCleanup } from './scheduled/daily-cleanup';

export const functions = [
    sendNotification,
    notificationDelivery,
    userRegistered,
    dailyCleanup,
    // Add more functions here as they're created
];
