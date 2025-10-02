import { EventSchemas, Inngest } from 'inngest';
import type { InngestEvents } from './events';

export const inngest = new Inngest({
    id: 'awe-pwa-app',
    schemas: new EventSchemas().fromRecord<InngestEvents>(),
    // middleware: [
    // ],
    retryFunction: async (attempt: number) => {
        return Math.min(Math.pow(2, attempt) * 1000, 60000);
    },
});

type SendFn = typeof inngest.send;
type SendPayload = Parameters<SendFn>[0];

export type AppEventPayload = Extract<SendPayload, { name: string }>;
export type InngestEvent = AppEventPayload | {
    name: 'inngest/function.invoked';
    data: any
};