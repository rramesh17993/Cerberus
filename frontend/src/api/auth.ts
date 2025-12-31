/**
 * 🔐 SecureScan Framework - Authentication API
 * 
 * API service for authentication and user management operations
 * 
 * Features:
 * - User authentication (login/logout/register)
 * - JWT token management
 * - Password reset and email verification
 * - User profile management
 * - API key management
 * - Session management
 * 
 * Author: SecureScan Team
 */

import { httpClient } from './client';
import type {
  User,
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  PasswordResetRequest,
  PasswordResetResponse,
  PasswordChangeRequest,
  EmailVerificationRequest,
  EmailVerificationResponse,
  APIKey,
  CreateAPIKeyRequest,
  CreateAPIKeyResponse,
  SessionInfo,
  UserProfile,
  UserSettings,
  APIResponse,
  PaginatedResponse,
  QueryParams
} from '@/types';

// =============================================================================
// 🔐 AUTHENTICATION ENDPOINTS
// =============================================================================

export const authAPI = {
  /**
   * User login
   */
  async login(credentials: LoginRequest): Promise<LoginResponse> {
    const response = await httpClient.post<LoginResponse>('/v1/auth/login', credentials);
    
    // Store tokens in client
    const { accessToken, refreshToken, expiresIn } = response.data;
    httpClient.setAuthTokens(accessToken, refreshToken, expiresIn);
    
    return response.data;
  },

  /**
   * User registration
   */
  async register(userData: RegisterRequest): Promise<RegisterResponse> {
    const response = await httpClient.post<RegisterResponse>('/v1/auth/register', userData);
    return response.data;
  },

  /**
   * User logout
   */
  async logout(): Promise<void> {
    try {
      await httpClient.post('/v1/auth/logout');
    } finally {
      // Always clear tokens, even if logout request fails
      httpClient.clearAuthTokens();
    }
  },

  /**
   * Refresh access token
   */
  async refreshToken(refreshTokenData: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    const response = await httpClient.post<RefreshTokenResponse>('/v1/auth/refresh', refreshTokenData);
    
    // Update tokens in client
    const { accessToken, refreshToken, expiresIn } = response.data;
    httpClient.setAuthTokens(accessToken, refreshToken, expiresIn);
    
    return response.data;
  },

  /**
   * Request password reset
   */
  async requestPasswordReset(email: PasswordResetRequest): Promise<PasswordResetResponse> {
    const response = await httpClient.post<PasswordResetResponse>('/v1/auth/password-reset', email);
    return response.data;
  },

  /**
   * Confirm password reset
   */
  async confirmPasswordReset(token: string, newPassword: string): Promise<void> {
    await httpClient.post('/v1/auth/password-reset/confirm', {
      token,
      newPassword
    });
  },

  /**
   * Change password (authenticated user)
   */
  async changePassword(passwordData: PasswordChangeRequest): Promise<void> {
    await httpClient.post('/v1/auth/password-change', passwordData);
  },

  /**
   * Verify email address
   */
  async verifyEmail(verificationData: EmailVerificationRequest): Promise<EmailVerificationResponse> {
    const response = await httpClient.post<EmailVerificationResponse>('/v1/auth/verify-email', verificationData);
    return response.data;
  },

  /**
   * Resend email verification
   */
  async resendEmailVerification(email: string): Promise<void> {
    await httpClient.post('/v1/auth/verify-email/resend', { email });
  },

  /**
   * Check authentication status
   */
  async checkAuth(): Promise<User> {
    const response = await httpClient.get<User>('/v1/auth/me');
    return response.data;
  },

  /**
   * Check if user is authenticated (client-side)
   */
  isAuthenticated(): boolean {
    return httpClient.isAuthenticated();
  }
};

// =============================================================================
// 👤 USER MANAGEMENT ENDPOINTS
// =============================================================================

export const userAPI = {
  /**
   * Get current user profile
   */
  async getProfile(): Promise<UserProfile> {
    const response = await httpClient.get<UserProfile>('/v1/users/profile');
    return response.data;
  },

  /**
   * Update user profile
   */
  async updateProfile(profileData: Partial<User>): Promise<User> {
    const response = await httpClient.patch<User>('/v1/users/profile', profileData);
    return response.data;
  },

  /**
   * Get user by ID (admin only)
   */
  async getUser(userId: string): Promise<User> {
    const response = await httpClient.get<User>(`/v1/users/${userId}`);
    return response.data;
  },

  /**
   * List users (admin only)
   */
  async listUsers(params?: QueryParams): Promise<PaginatedResponse<User>> {
    return await httpClient.getPaginated<User>('/v1/users', params);
  },

  /**
   * Create user (admin only)
   */
  async createUser(userData: Partial<User>): Promise<User> {
    const response = await httpClient.post<User>('/v1/users', userData);
    return response.data;
  },

  /**
   * Update user (admin only)
   */
  async updateUser(userId: string, userData: Partial<User>): Promise<User> {
    const response = await httpClient.patch<User>(`/v1/users/${userId}`, userData);
    return response.data;
  },

  /**
   * Delete user (admin only)
   */
  async deleteUser(userId: string): Promise<void> {
    await httpClient.delete(`/v1/users/${userId}`);
  },

  /**
   * Upload avatar
   */
  async uploadAvatar(file: File, onProgress?: (progress: number) => void): Promise<{ avatarUrl: string }> {
    const response = await httpClient.uploadFile<{ avatarUrl: string }>(
      '/v1/users/avatar',
      file,
      onProgress
    );
    return response.data;
  },

  /**
   * Delete avatar
   */
  async deleteAvatar(): Promise<void> {
    await httpClient.delete('/v1/users/avatar');
  }
};

// =============================================================================
// 🔑 API KEY MANAGEMENT ENDPOINTS
// =============================================================================

export const apiKeyAPI = {
  /**
   * List user's API keys
   */
  async listAPIKeys(params?: QueryParams): Promise<PaginatedResponse<APIKey>> {
    return await httpClient.getPaginated<APIKey>('/v1/auth/api-keys', params);
  },

  /**
   * Create new API key
   */
  async createAPIKey(keyData: CreateAPIKeyRequest): Promise<CreateAPIKeyResponse> {
    const response = await httpClient.post<CreateAPIKeyResponse>('/v1/auth/api-keys', keyData);
    return response.data;
  },

  /**
   * Get API key details
   */
  async getAPIKey(keyId: string): Promise<APIKey> {
    const response = await httpClient.get<APIKey>(`/v1/auth/api-keys/${keyId}`);
    return response.data;
  },

  /**
   * Update API key
   */
  async updateAPIKey(keyId: string, keyData: Partial<APIKey>): Promise<APIKey> {
    const response = await httpClient.patch<APIKey>(`/v1/auth/api-keys/${keyId}`, keyData);
    return response.data;
  },

  /**
   * Revoke API key
   */
  async revokeAPIKey(keyId: string): Promise<void> {
    await httpClient.delete(`/v1/auth/api-keys/${keyId}`);
  },

  /**
   * Regenerate API key
   */
  async regenerateAPIKey(keyId: string): Promise<CreateAPIKeyResponse> {
    const response = await httpClient.post<CreateAPIKeyResponse>(`/v1/auth/api-keys/${keyId}/regenerate`);
    return response.data;
  }
};

// =============================================================================
// 📱 SESSION MANAGEMENT ENDPOINTS
// =============================================================================

export const sessionAPI = {
  /**
   * List user sessions
   */
  async listSessions(params?: QueryParams): Promise<PaginatedResponse<SessionInfo>> {
    return await httpClient.getPaginated<SessionInfo>('/v1/auth/sessions', params);
  },

  /**
   * Get current session
   */
  async getCurrentSession(): Promise<SessionInfo> {
    const response = await httpClient.get<SessionInfo>('/v1/auth/sessions/current');
    return response.data;
  },

  /**
   * Revoke session
   */
  async revokeSession(sessionId: string): Promise<void> {
    await httpClient.delete(`/v1/auth/sessions/${sessionId}`);
  },

  /**
   * Revoke all other sessions
   */
  async revokeAllOtherSessions(): Promise<void> {
    await httpClient.post('/v1/auth/sessions/revoke-others');
  },

  /**
   * Revoke all sessions (logout everywhere)
   */
  async revokeAllSessions(): Promise<void> {
    await httpClient.post('/v1/auth/sessions/revoke-all');
  }
};

// =============================================================================
// ⚙️ USER SETTINGS ENDPOINTS
// =============================================================================

export const settingsAPI = {
  /**
   * Get user settings
   */
  async getSettings(): Promise<UserSettings> {
    const response = await httpClient.get<UserSettings>('/v1/users/settings');
    return response.data;
  },

  /**
   * Update user settings
   */
  async updateSettings(settings: Partial<UserSettings>): Promise<UserSettings> {
    const response = await httpClient.patch<UserSettings>('/v1/users/settings', settings);
    return response.data;
  },

  /**
   * Reset settings to defaults
   */
  async resetSettings(): Promise<UserSettings> {
    const response = await httpClient.post<UserSettings>('/v1/users/settings/reset');
    return response.data;
  },

  /**
   * Export user data
   */
  async exportUserData(format: 'json' | 'csv' = 'json'): Promise<void> {
    await httpClient.downloadFile(`/v1/users/export?format=${format}`, `user-data.${format}`);
  },

  /**
   * Delete user account
   */
  async deleteAccount(password: string): Promise<void> {
    await httpClient.post('/v1/users/delete-account', { password });
  }
};

// =============================================================================
// 🔔 NOTIFICATION ENDPOINTS
// =============================================================================

export const notificationAPI = {
  /**
   * Get user notifications
   */
  async getNotifications(params?: QueryParams): Promise<PaginatedResponse<Notification>> {
    return await httpClient.getPaginated<Notification>('/v1/notifications', params);
  },

  /**
   * Mark notification as read
   */
  async markAsRead(notificationId: string): Promise<void> {
    await httpClient.patch(`/v1/notifications/${notificationId}/read`);
  },

  /**
   * Mark all notifications as read
   */
  async markAllAsRead(): Promise<void> {
    await httpClient.patch('/v1/notifications/read-all');
  },

  /**
   * Delete notification
   */
  async deleteNotification(notificationId: string): Promise<void> {
    await httpClient.delete(`/v1/notifications/${notificationId}`);
  },

  /**
   * Get unread count
   */
  async getUnreadCount(): Promise<{ count: number }> {
    const response = await httpClient.get<{ count: number }>('/v1/notifications/unread-count');
    return response.data;
  }
};

// =============================================================================
// 🚨 AUDIT LOG ENDPOINTS
// =============================================================================

export const auditAPI = {
  /**
   * Get user audit logs
   */
  async getAuditLogs(params?: QueryParams): Promise<PaginatedResponse<AuditLog>> {
    return await httpClient.getPaginated<AuditLog>('/v1/audit', params);
  },

  /**
   * Get audit log entry
   */
  async getAuditLog(logId: string): Promise<AuditLog> {
    const response = await httpClient.get<AuditLog>(`/v1/audit/${logId}`);
    return response.data;
  }
};

// =============================================================================
// 🔐 TWO-FACTOR AUTHENTICATION ENDPOINTS
// =============================================================================

export const twoFactorAPI = {
  /**
   * Generate 2FA setup QR code
   */
  async generateSetup(): Promise<{ qrCode: string; secret: string; backupCodes: string[] }> {
    const response = await httpClient.post<{ qrCode: string; secret: string; backupCodes: string[] }>('/v1/auth/2fa/setup');
    return response.data;
  },

  /**
   * Enable 2FA
   */
  async enable(token: string, backupCodes: string[]): Promise<void> {
    await httpClient.post('/v1/auth/2fa/enable', { token, backupCodes });
  },

  /**
   * Disable 2FA
   */
  async disable(password: string): Promise<void> {
    await httpClient.post('/v1/auth/2fa/disable', { password });
  },

  /**
   * Verify 2FA token
   */
  async verify(token: string): Promise<void> {
    await httpClient.post('/v1/auth/2fa/verify', { token });
  },

  /**
   * Generate new backup codes
   */
  async generateBackupCodes(password: string): Promise<{ backupCodes: string[] }> {
    const response = await httpClient.post<{ backupCodes: string[] }>('/v1/auth/2fa/backup-codes', { password });
    return response.data;
  }
};

// =============================================================================
// 🔗 SOCIAL AUTH ENDPOINTS
// =============================================================================

export const socialAuthAPI = {
  /**
   * Get OAuth URL for provider
   */
  async getOAuthURL(provider: 'github' | 'google' | 'microsoft'): Promise<{ url: string; state: string }> {
    const response = await httpClient.get<{ url: string; state: string }>(`/v1/auth/oauth/${provider}/url`);
    return response.data;
  },

  /**
   * Complete OAuth callback
   */
  async completeOAuth(provider: string, code: string, state: string): Promise<LoginResponse> {
    const response = await httpClient.post<LoginResponse>(`/v1/auth/oauth/${provider}/callback`, {
      code,
      state
    });

    // Store tokens in client
    const { accessToken, refreshToken, expiresIn } = response.data;
    httpClient.setAuthTokens(accessToken, refreshToken, expiresIn);
    
    return response.data;
  },

  /**
   * Link social account
   */
  async linkAccount(provider: string, code: string, state: string): Promise<void> {
    await httpClient.post(`/v1/auth/oauth/${provider}/link`, {
      code,
      state
    });
  },

  /**
   * Unlink social account
   */
  async unlinkAccount(provider: string): Promise<void> {
    await httpClient.delete(`/v1/auth/oauth/${provider}/unlink`);
  }
};

// =============================================================================
// 🚀 EXPORT ALL AUTH SERVICES
// =============================================================================

export const auth = {
  ...authAPI,
  user: userAPI,
  apiKey: apiKeyAPI,
  session: sessionAPI,
  settings: settingsAPI,
  notification: notificationAPI,
  audit: auditAPI,
  twoFactor: twoFactorAPI,
  social: socialAuthAPI
};

export default auth;