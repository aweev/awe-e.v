// lib/errors/auth.errors.ts 
export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

export class InvalidCredentialsError extends AuthError {
  public code?: string;

  constructor(message = 'Invalid email or password.', code?: string) {
    super(message);
    this.name = 'InvalidCredentialsError';
    this.code = code;
  }
}

export class AccountExistsError extends AuthError {
  constructor(message = 'An account with this email already exists.') {
    super(message);
    this.name = 'AccountExistsError';
  }
}

export class InvalidTokenError extends AuthError {
  constructor(message = 'The provided token is invalid or has expired.') {
    super(message);
    this.name = 'InvalidTokenError';
  }
}

export class MfaRequiredError extends AuthError {
  public mfaToken: string;

  constructor(mfaToken: string, message = 'Multi-factor authentication is required.') {
    super(message);
    this.name = 'MfaRequiredError';
    this.mfaToken = mfaToken;
  }
}

export class AccountExistsVerifiedError extends AccountExistsError {
  constructor(message = 'This account already exists. Please log in.') {
    super(message);
    this.name = 'AccountExistsVerifiedError';
  }
}

export class AccountExistsUnverifiedError extends AccountExistsError {
  constructor(message = 'Account exists but is not verified. A new verification email has been sent.') {
    super(message);
    this.name = 'AccountExistsUnverifiedError';
  }
}

export class PasswordPolicyError extends Error {
  constructor(
    public issues: string[],
    message = 'Password does not meet security requirements'
  ) {
    super(message);
    this.name = 'PasswordPolicyError';
  }
}

export class AccountLockedError extends Error {
  constructor(
    public lockedUntil: Date,
    message = 'Account has been temporarily locked due to too many failed login attempts. Please try again later.'
  ) {
    super(message);
    this.name = 'AccountLockedError';
  }
}

export class NewDeviceError extends Error {
  constructor(
    public deviceId: string,
    message = 'New device detected. Please verify this device.'
  ) {
    super(message);
    this.name = 'NewDeviceError';
  }
}