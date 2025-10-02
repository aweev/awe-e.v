// lib/i18n.ts
import { getRequestConfig } from 'next-intl/server';

export const locales = ['en', 'de', 'fr'] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = 'en';

import enMessages from '@/messages/en.json';
import deMessages from '@/messages/de.json';
import frMessages from '@/messages/fr.json';

export type Messages = typeof enMessages;

const allTranslations: Record<Locale, Messages> = {
  en: enMessages,
  de: deMessages as unknown as Messages,
  fr: frMessages as unknown as Messages,
};

export const localeNames = {
  en: 'English',
  de: 'Deutsch',
  fr: 'Français',
} as const;

export const localeFlags = {
  en: '🇺🇸',
  de: '🇩🇪',
  fr: '🇫🇷',
} as const;

export function getTranslations(locale: Locale): Messages {
  return allTranslations[locale] ?? allTranslations.en;
}

export default getRequestConfig(async ({ locale }) => {
  const validLocale = locales.includes(locale as Locale) ? (locale as Locale) : defaultLocale;

  return {
    locale: validLocale,
    messages: getTranslations(validLocale),
  };
});