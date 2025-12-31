/**
 * 🌐 SecureScan Framework - API Types
 * 
 * TypeScript type definitions for API communication and common utilities
 * 
 * Features:
 * - API request/response types
 * - Error handling types
 * - Pagination and filtering
 * - Common UI component types
 * - Utility types
 * 
 * Author: SecureScan Team
 */

// =============================================================================
// 🌐 API RESPONSE TYPES
// =============================================================================

export interface APIResponse<T = any> {
  data: T;
  message?: string;
  success: boolean;
  timestamp: string;
  requestId?: string;
}

export interface PaginatedResponse<T = any> {
  data: T[];
  pagination: PaginationInfo;
  message?: string;
  success: boolean;
  timestamp: string;
  requestId?: string;
}

export interface PaginationInfo {
  page: number;
  pageSize: number;
  totalItems: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export interface APIError {
  error: string;
  detail: string;
  code?: string;
  statusCode: number;
  timestamp: string;
  requestId?: string;
  validationErrors?: ValidationError[];
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
  value?: any;
}

// =============================================================================
// 🔍 QUERY TYPES
// =============================================================================

export interface PaginationParams {
  page?: number;
  pageSize?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface FilterParams {
  search?: string;
  filters?: Record<string, any>;
  dateRange?: DateRange;
}

export interface DateRange {
  start: string;
  end: string;
}

export interface QueryParams extends PaginationParams, FilterParams {
  include?: string[];
  exclude?: string[];
}

// =============================================================================
// 📊 DASHBOARD TYPES
// =============================================================================

export interface DashboardData {
  overview: DashboardOverview;
  recentScans: RecentScan[];
  vulnerabilityTrends: VulnerabilityTrend[];
  scannerMetrics: ScannerMetric[];
  projectSummary: ProjectSummary[];
  alerts: DashboardAlert[];
}

export interface DashboardOverview {
  totalProjects: number;
  totalScans: number;
  totalVulnerabilities: number;
  activeScans: number;
  criticalVulnerabilities: number;
  projectsWithIssues: number;
  scansToday: number;
  vulnerabilitiesFixed: number;
  trendsData: TrendData[];
}

export interface TrendData {
  date: string;
  scans: number;
  vulnerabilities: number;
  resolved: number;
}

export interface RecentScan {
  id: string;
  projectName: string;
  status: string;
  vulnerabilities: number;
  duration: number;
  completedAt: string;
}

export interface VulnerabilityTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScannerMetric {
  type: string;
  name: string;
  scansRun: number;
  vulnerabilitiesFound: number;
  avgDuration: number;
  successRate: number;
}

export interface ProjectSummary {
  id: string;
  name: string;
  vulnerabilities: number;
  lastScan: string;
  riskScore: number;
  trend: 'up' | 'down' | 'stable';
}

export interface DashboardAlert {
  id: string;
  type: 'info' | 'warning' | 'error' | 'success';
  title: string;
  message: string;
  actionUrl?: string;
  actionText?: string;
  createdAt: string;
  dismissible: boolean;
}

// =============================================================================
// 📈 ANALYTICS TYPES
// =============================================================================

export interface AnalyticsData {
  timeRange: string;
  metrics: AnalyticsMetrics;
  charts: AnalyticsCharts;
  insights: AnalyticsInsight[];
}

export interface AnalyticsMetrics {
  scanFrequency: MetricValue;
  vulnerabilityDetection: MetricValue;
  resolutionTime: MetricValue;
  falsePositiveRate: MetricValue;
  securityPosture: MetricValue;
}

export interface MetricValue {
  current: number;
  previous: number;
  change: number;
  changePercentage: number;
  trend: 'up' | 'down' | 'stable';
  unit: string;
}

export interface AnalyticsCharts {
  vulnerabilityTrends: ChartData;
  scannerPerformance: ChartData;
  projectRiskDistribution: ChartData;
  timeToResolution: ChartData;
  vulnerabilityCategories: ChartData;
}

export interface ChartData {
  type: 'line' | 'bar' | 'pie' | 'area' | 'scatter';
  data: ChartDataPoint[];
  labels: string[];
  datasets: ChartDataset[];
}

export interface ChartDataPoint {
  x: string | number;
  y: number;
  label?: string;
  color?: string;
}

export interface ChartDataset {
  label: string;
  data: number[];
  backgroundColor?: string | string[];
  borderColor?: string;
  borderWidth?: number;
  fill?: boolean;
}

export interface AnalyticsInsight {
  id: string;
  type: 'trend' | 'anomaly' | 'recommendation' | 'alert';
  title: string;
  description: string;
  impact: 'low' | 'medium' | 'high';
  confidence: number;
  actionable: boolean;
  actions?: InsightAction[];
  createdAt: string;
}

export interface InsightAction {
  type: string;
  label: string;
  url?: string;
  data?: Record<string, any>;
}

// =============================================================================
// 🎨 UI COMPONENT TYPES
// =============================================================================

export interface TableColumn<T = any> {
  key: string;
  label: string;
  sortable?: boolean;
  filterable?: boolean;
  width?: string;
  align?: 'left' | 'center' | 'right';
  render?: (value: any, row: T) => React.ReactNode;
  hidden?: boolean;
}

export interface TableAction<T = any> {
  label: string;
  icon?: string;
  onClick: (row: T) => void;
  disabled?: (row: T) => boolean;
  variant?: 'default' | 'destructive' | 'outline' | 'secondary';
  requiresConfirmation?: boolean;
  confirmationMessage?: string;
}

export interface FormField {
  name: string;
  label: string;
  type: 'text' | 'email' | 'password' | 'number' | 'select' | 'textarea' | 'checkbox' | 'radio' | 'date' | 'file';
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
  options?: SelectOption[];
  validation?: ValidationRule[];
  description?: string;
  defaultValue?: any;
}

export interface SelectOption {
  value: string | number;
  label: string;
  disabled?: boolean;
  icon?: string;
}

export interface ValidationRule {
  type: 'required' | 'email' | 'min' | 'max' | 'pattern' | 'custom';
  value?: any;
  message: string;
}

export interface BreadcrumbItem {
  label: string;
  href?: string;
  active?: boolean;
}

export interface TabItem {
  id: string;
  label: string;
  icon?: string;
  content: React.ReactNode;
  disabled?: boolean;
  badge?: string | number;
}

export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
  preventClose?: boolean;
}

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  description?: string;
  action?: ToastAction;
  duration?: number;
  dismissible?: boolean;
}

export interface ToastAction {
  label: string;
  onClick: () => void;
}

// =============================================================================
// 🔄 STATE TYPES
// =============================================================================

export interface LoadingState {
  isLoading: boolean;
  error?: string | null;
  lastUpdated?: string;
}

export interface AsyncState<T> extends LoadingState {
  data?: T;
}

export interface ListState<T> extends LoadingState {
  items: T[];
  pagination?: PaginationInfo;
  filters?: Record<string, any>;
  search?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

// =============================================================================
// 🔧 UTILITY TYPES
// =============================================================================

export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

export type PartialExcept<T, K extends keyof T> = Partial<T> & Pick<T, K>;

export type StringKeys<T> = Extract<keyof T, string>;

export type ValueOf<T> = T[keyof T];

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type DeepRequired<T> = {
  [P in keyof T]-?: T[P] extends object ? DeepRequired<T[P]> : T[P];
};

// =============================================================================
// 🌍 ENVIRONMENT TYPES
// =============================================================================

export interface AppConfig {
  apiUrl: string;
  wsUrl: string;
  appName: string;
  appVersion: string;
  environment: 'development' | 'staging' | 'production';
  features: FeatureFlags;
  limits: AppLimits;
  external: ExternalServices;
}

export interface FeatureFlags {
  realTimeUpdates: boolean;
  advancedAnalytics: boolean;
  customScanners: boolean;
  apiKeyAuth: boolean;
  ssoIntegration: boolean;
  webhookNotifications: boolean;
  reportExports: boolean;
  darkMode: boolean;
}

export interface AppLimits {
  maxProjectsPerUser: number;
  maxScansPerProject: number;
  maxFileSize: number; // MB
  scanTimeout: number; // minutes
  apiRateLimit: number; // requests per hour
  maxConcurrentScans: number;
}

export interface ExternalServices {
  documentation: string;
  support: string;
  statusPage: string;
  github: string;
  slack: string;
  twitter: string;
}

// =============================================================================
// 📱 THEME TYPES
// =============================================================================

export interface Theme {
  name: string;
  colors: ThemeColors;
  typography: ThemeTypography;
  spacing: ThemeSpacing;
  breakpoints: ThemeBreakpoints;
}

export interface ThemeColors {
  primary: string;
  secondary: string;
  background: string;
  foreground: string;
  muted: string;
  accent: string;
  destructive: string;
  border: string;
  input: string;
  ring: string;
}

export interface ThemeTypography {
  fontFamily: {
    sans: string[];
    mono: string[];
  };
  fontSize: Record<string, string>;
  fontWeight: Record<string, number>;
  lineHeight: Record<string, string>;
}

export interface ThemeSpacing {
  [key: string]: string;
}

export interface ThemeBreakpoints {
  sm: string;
  md: string;
  lg: string;
  xl: string;
  '2xl': string;
}

// =============================================================================
// 🔍 SEARCH TYPES
// =============================================================================

export interface SearchResult<T = any> {
  id: string;
  type: string;
  title: string;
  description?: string;
  url: string;
  data: T;
  relevance: number;
  highlights?: string[];
}

export interface SearchFilters {
  types?: string[];
  dateRange?: DateRange;
  projects?: string[];
  users?: string[];
  tags?: string[];
  severity?: string[];
  status?: string[];
}

export interface SearchQuery {
  query: string;
  filters?: SearchFilters;
  pagination?: PaginationParams;
  includeArchived?: boolean;
}

export interface SearchResponse<T = any> {
  results: SearchResult<T>[];
  total: number;
  took: number; // milliseconds
  suggestions?: string[];
  pagination: PaginationInfo;
}

// =============================================================================
// 📊 EXPORT TYPES
// =============================================================================

export interface ExportRequest {
  type: 'csv' | 'json' | 'pdf' | 'xlsx' | 'sarif';
  data: any;
  filename?: string;
  options?: ExportOptions;
}

export interface ExportOptions {
  includeHeaders?: boolean;
  dateFormat?: string;
  delimiter?: string;
  encoding?: string;
  template?: string;
}

export interface ExportResponse {
  url: string;
  filename: string;
  size: number;
  expiresAt: string;
}

// =============================================================================
// 🔔 NOTIFICATION TYPES (Extended)
// =============================================================================

export interface NotificationChannel {
  id: string;
  type: 'email' | 'slack' | 'webhook' | 'teams' | 'discord';
  name: string;
  config: NotificationChannelConfig;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface NotificationChannelConfig {
  [key: string]: any;
  // Email
  recipients?: string[];
  template?: string;
  // Slack
  webhookUrl?: string;
  channel?: string;
  username?: string;
  // Webhook
  url?: string;
  headers?: Record<string, string>;
  method?: 'POST' | 'PUT' | 'PATCH';
}

export interface NotificationTemplate {
  id: string;
  name: string;
  type: string;
  subject: string;
  body: string;
  variables: string[];
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

// Re-export all types from other modules
export * from './auth';
export * from './scanning';