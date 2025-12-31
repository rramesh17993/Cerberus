/**
 * 🔐 SecureScan Framework - Authentication Types
 * 
 * TypeScript type definitions for authentication, users, and authorization
 * 
 * Features:
 * - User management types
 * - JWT token handling
 * - Role-based access control (RBAC)
 * - API key authentication
 * - Session management
 * 
 * Author: SecureScan Team
 */

// =============================================================================
// 👤 USER TYPES
// =============================================================================

export interface User {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  status: UserStatus;
  isActive: boolean;
  isVerified: boolean;
  lastActivity: string;
  createdAt: string;
  updatedAt: string;
  avatar?: string;
  timezone?: string;
  preferences?: UserPreferences;
}

export type UserRole = 'admin' | 'developer' | 'scanner' | 'viewer';

export type UserStatus = 'active' | 'inactive' | 'suspended' | 'pending';

export interface UserPreferences {
  theme: 'light' | 'dark' | 'system';
  language: string;
  notifications: NotificationPreferences;
  dashboard: DashboardPreferences;
}

export interface NotificationPreferences {
  email: boolean;
  push: boolean;
  scanComplete: boolean;
  vulnerabilityFound: boolean;
  weeklyReport: boolean;
}

export interface DashboardPreferences {
  defaultView: 'overview' | 'projects' | 'scans' | 'vulnerabilities';
  chartsTimeRange: '7d' | '30d' | '90d' | '1y';
  vulnerabilityColumns: string[];
  scanColumns: string[];
}

// =============================================================================
// 🔐 AUTHENTICATION TYPES
// =============================================================================

export interface LoginRequest {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface LoginResponse {
  user: User;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface RegisterRequest {
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  password: string;
  confirmPassword: string;
}

export interface RegisterResponse {
  user: User;
  message: string;
  verificationRequired: boolean;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface PasswordResetRequest {
  email: string;
}

export interface PasswordResetResponse {
  message: string;
  resetRequired: boolean;
}

export interface PasswordChangeRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface EmailVerificationRequest {
  token: string;
}

export interface EmailVerificationResponse {
  user: User;
  message: string;
}

// =============================================================================
// 🔑 API KEY TYPES
// =============================================================================

export interface APIKey {
  id: string;
  name: string;
  keyPrefix: string;
  permissions: APIKeyPermission[];
  isActive: boolean;
  expiresAt?: string;
  lastUsed?: string;
  createdAt: string;
  updatedAt: string;
  usage: APIKeyUsage;
}

export interface APIKeyPermission {
  resource: string;
  actions: string[];
}

export interface APIKeyUsage {
  totalRequests: number;
  requestsToday: number;
  requestsThisMonth: number;
  lastRequestIp?: string;
  lastRequestUserAgent?: string;
}

export interface CreateAPIKeyRequest {
  name: string;
  permissions: APIKeyPermission[];
  expiresAt?: string;
}

export interface CreateAPIKeyResponse {
  apiKey: APIKey;
  secretKey: string; // Only returned once
}

// =============================================================================
// 🛡️ AUTHORIZATION TYPES
// =============================================================================

export interface Permission {
  resource: string;
  action: string;
  conditions?: Record<string, any>;
}

export interface RolePermissions {
  role: UserRole;
  permissions: Permission[];
}

export interface AuthContext {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  permissions: Permission[];
  hasPermission: (resource: string, action: string) => boolean;
  hasRole: (role: UserRole | UserRole[]) => boolean;
}

// =============================================================================
// 📱 SESSION TYPES
// =============================================================================

export interface SessionInfo {
  id: string;
  userId: string;
  deviceInfo: DeviceInfo;
  ipAddress: string;
  location?: string;
  isActive: boolean;
  isCurrent: boolean;
  createdAt: string;
  lastActivity: string;
  expiresAt: string;
}

export interface DeviceInfo {
  type: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  os?: string;
  browser?: string;
  userAgent: string;
}

// =============================================================================
// 🔔 NOTIFICATION TYPES
// =============================================================================

export interface Notification {
  id: string;
  userId: string;
  type: NotificationType;
  title: string;
  message: string;
  data?: Record<string, any>;
  isRead: boolean;
  createdAt: string;
  expiresAt?: string;
}

export type NotificationType = 
  | 'scan_complete'
  | 'vulnerability_found'
  | 'scan_failed'
  | 'project_shared'
  | 'user_mention'
  | 'system_maintenance'
  | 'security_alert';

// =============================================================================
// 🚨 AUDIT TYPES
// =============================================================================

export interface AuditLog {
  id: string;
  userId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  details: Record<string, any>;
  ipAddress: string;
  userAgent: string;
  timestamp: string;
  success: boolean;
  errorMessage?: string;
}

export type AuditAction = 
  | 'user.login'
  | 'user.logout' 
  | 'user.register'
  | 'user.password_change'
  | 'project.create'
  | 'project.update'
  | 'project.delete'
  | 'scan.start'
  | 'scan.cancel'
  | 'vulnerability.update'
  | 'api_key.create'
  | 'api_key.revoke';

// =============================================================================
// 📊 USER PROFILE TYPES
// =============================================================================

export interface UserProfile {
  user: User;
  stats: UserStats;
  recentActivity: UserActivity[];
  projects: UserProject[];
}

export interface UserStats {
  totalScans: number;
  totalVulnerabilities: number;
  projectsOwned: number;
  projectsShared: number;
  lastScanDate?: string;
  avgScansPerWeek: number;
}

export interface UserActivity {
  id: string;
  type: string;
  description: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

export interface UserProject {
  id: string;
  name: string;
  role: 'owner' | 'collaborator' | 'viewer';
  lastActivity: string;
}

// =============================================================================
// 🔧 SETTINGS TYPES
// =============================================================================

export interface UserSettings {
  id: string;
  userId: string;
  general: GeneralSettings;
  security: SecuritySettings;
  notifications: NotificationSettings;
  integrations: IntegrationSettings;
  updatedAt: string;
}

export interface GeneralSettings {
  displayName: string;
  timezone: string;
  language: string;
  dateFormat: string;
  timeFormat: '12h' | '24h';
}

export interface SecuritySettings {
  twoFactorEnabled: boolean;
  sessionTimeout: number;
  ipWhitelist: string[];
  allowedDevices: DeviceInfo[];
}

export interface NotificationSettings {
  channels: NotificationChannel[];
  types: NotificationTypeSettings[];
}

export interface NotificationChannel {
  type: 'email' | 'push' | 'webhook';
  enabled: boolean;
  config: Record<string, any>;
}

export interface NotificationTypeSettings {
  type: NotificationType;
  enabled: boolean;
  channels: string[];
  threshold?: number;
}

export interface IntegrationSettings {
  slack?: SlackIntegration;
  teams?: TeamsIntegration;
  jira?: JiraIntegration;
  github?: GitHubIntegration;
}

export interface SlackIntegration {
  enabled: boolean;
  webhookUrl: string;
  channels: string[];
}

export interface TeamsIntegration {
  enabled: boolean;
  webhookUrl: string;
}

export interface JiraIntegration {
  enabled: boolean;
  serverUrl: string;
  username: string;
  apiToken: string;
  projectKey: string;
}

export interface GitHubIntegration {
  enabled: boolean;
  accessToken: string;
  organizations: string[];
}