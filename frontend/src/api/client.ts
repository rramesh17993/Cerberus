/**
 * 🌐 SecureScan Framework - API Client
 * 
 * Centralized API client for communication with the SecureScan backend
 * 
 * Features:
 * - Axios-based HTTP client with interceptors
 * - Automatic JWT token handling
 * - Request/response logging
 * - Error handling and retry logic
 * - TypeScript support for all endpoints
 * - Real-time WebSocket connections
 * 
 * Author: SecureScan Team
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import { 
  APIResponse, 
  PaginatedResponse, 
  APIError, 
  QueryParams 
} from '@/types';

// =============================================================================
// 🔧 API CLIENT CONFIGURATION
// =============================================================================

interface APIClientConfig {
  baseURL: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  enableLogging: boolean;
}

const DEFAULT_CONFIG: APIClientConfig = {
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 30000,
  retryAttempts: 3,
  retryDelay: 1000,
  enableLogging: import.meta.env.VITE_DEBUG === 'true' || import.meta.env.DEV
};

// =============================================================================
// 🔐 TOKEN MANAGEMENT
// =============================================================================

class TokenManager {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private tokenExpiry: number | null = null;

  constructor() {
    this.loadTokensFromStorage();
  }

  private loadTokensFromStorage(): void {
    try {
      this.accessToken = localStorage.getItem('securescan_access_token');
      this.refreshToken = localStorage.getItem('securescan_refresh_token');
      const expiry = localStorage.getItem('securescan_token_expiry');
      this.tokenExpiry = expiry ? parseInt(expiry, 10) : null;
    } catch (error) {
      console.warn('Failed to load tokens from storage:', error);
    }
  }

  private saveTokensToStorage(): void {
    try {
      if (this.accessToken) {
        localStorage.setItem('securescan_access_token', this.accessToken);
      } else {
        localStorage.removeItem('securescan_access_token');
      }

      if (this.refreshToken) {
        localStorage.setItem('securescan_refresh_token', this.refreshToken);
      } else {
        localStorage.removeItem('securescan_refresh_token');
      }

      if (this.tokenExpiry) {
        localStorage.setItem('securescan_token_expiry', this.tokenExpiry.toString());
      } else {
        localStorage.removeItem('securescan_token_expiry');
      }
    } catch (error) {
      console.warn('Failed to save tokens to storage:', error);
    }
  }

  setTokens(accessToken: string, refreshToken: string, expiresIn: number): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenExpiry = Date.now() + (expiresIn * 1000);
    this.saveTokensToStorage();
  }

  getAccessToken(): string | null {
    if (this.isTokenExpired()) {
      return null;
    }
    return this.accessToken;
  }

  getRefreshToken(): string | null {
    return this.refreshToken;
  }

  isTokenExpired(): boolean {
    if (!this.tokenExpiry) {
      return true;
    }
    // Check if token expires within next 5 minutes
    return Date.now() >= (this.tokenExpiry - 300000);
  }

  clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;
    this.saveTokensToStorage();
  }

  isAuthenticated(): boolean {
    return !!this.accessToken && !this.isTokenExpired();
  }
}

// =============================================================================
// 🌐 HTTP CLIENT
// =============================================================================

class HTTPClient {
  private client: AxiosInstance;
  private tokenManager: TokenManager;
  private config: APIClientConfig;
  private isRefreshing = false;
  private failedQueue: Array<{
    resolve: (value: string) => void;
    reject: (error: any) => void;
  }> = [];

  constructor(config: Partial<APIClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.tokenManager = new TokenManager();
    this.client = this.createAxiosInstance();
    this.setupInterceptors();
  }

  private createAxiosInstance(): AxiosInstance {
    return axios.create({
      baseURL: this.config.baseURL,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });
  }

  private setupInterceptors(): void {
    // Request interceptor for adding auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = this.tokenManager.getAccessToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        // Add request ID for tracing
        const requestId = this.generateRequestId();
        config.headers['X-Request-ID'] = requestId;

        if (this.config.enableLogging) {
          console.log('🌐 API Request:', {
            method: config.method?.toUpperCase(),
            url: config.url,
            requestId,
            data: config.data
          });
        }

        return config;
      },
      (error) => {
        if (this.config.enableLogging) {
          console.error('❌ API Request Error:', error);
        }
        return Promise.reject(error);
      }
    );

    // Response interceptor for handling auth errors
    this.client.interceptors.response.use(
      (response) => {
        if (this.config.enableLogging) {
          console.log('✅ API Response:', {
            status: response.status,
            url: response.config.url,
            requestId: response.config.headers['X-Request-ID'],
            data: response.data
          });
        }
        return response;
      },
      async (error: AxiosError) => {
        const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

        if (this.config.enableLogging) {
          console.error('❌ API Response Error:', {
            status: error.response?.status,
            url: error.config?.url,
            requestId: error.config?.headers?.['X-Request-ID'],
            message: error.message,
            data: error.response?.data
          });
        }

        // Handle 401 Unauthorized
        if (error.response?.status === 401 && !originalRequest._retry) {
          if (this.isRefreshing) {
            // Wait for refresh to complete
            return new Promise((resolve, reject) => {
              this.failedQueue.push({ resolve, reject });
            }).then((token) => {
              if (originalRequest.headers) {
                originalRequest.headers.Authorization = `Bearer ${token}`;
              }
              return this.client(originalRequest);
            }).catch((err) => {
              return Promise.reject(err);
            });
          }

          originalRequest._retry = true;
          this.isRefreshing = true;

          try {
            const newToken = await this.refreshAccessToken();
            this.processQueue(null, newToken);
            
            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
            }
            
            return this.client(originalRequest);
          } catch (refreshError) {
            this.processQueue(refreshError, null);
            this.tokenManager.clearTokens();
            
            // Redirect to login or emit authentication event
            window.dispatchEvent(new CustomEvent('auth:logout'));
            
            return Promise.reject(refreshError);
          } finally {
            this.isRefreshing = false;
          }
        }

        return Promise.reject(this.transformError(error));
      }
    );
  }

  private processQueue(error: any, token: string | null = null): void {
    this.failedQueue.forEach(({ resolve, reject }) => {
      if (error) {
        reject(error);
      } else {
        resolve(token as string);
      }
    });

    this.failedQueue = [];
  }

  private async refreshAccessToken(): Promise<string> {
    const refreshToken = this.tokenManager.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await axios.post(`${this.config.baseURL}/v1/auth/refresh`, {
        refreshToken
      });

      const { accessToken, refreshToken: newRefreshToken, expiresIn } = response.data.data;
      this.tokenManager.setTokens(accessToken, newRefreshToken, expiresIn);
      
      return accessToken;
    } catch (error) {
      this.tokenManager.clearTokens();
      throw error;
    }
  }

  private transformError(error: AxiosError): APIError {
    const response = error.response;
    
    if (response?.data && typeof response.data === 'object') {
      return response.data as APIError;
    }

    return {
      error: 'Network Error',
      detail: error.message || 'An unexpected error occurred',
      statusCode: response?.status || 0,
      timestamp: new Date().toISOString()
    };
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // =============================================================================
  // 🔧 HTTP METHODS
  // =============================================================================

  async get<T = any>(
    url: string, 
    params?: QueryParams, 
    config?: AxiosRequestConfig
  ): Promise<APIResponse<T>> {
    const response = await this.client.get(url, {
      params,
      ...config
    });
    return response.data;
  }

  async getPaginated<T = any>(
    url: string, 
    params?: QueryParams, 
    config?: AxiosRequestConfig
  ): Promise<PaginatedResponse<T>> {
    const response = await this.client.get(url, {
      params,
      ...config
    });
    return response.data;
  }

  async post<T = any>(
    url: string, 
    data?: any, 
    config?: AxiosRequestConfig
  ): Promise<APIResponse<T>> {
    const response = await this.client.post(url, data, config);
    return response.data;
  }

  async put<T = any>(
    url: string, 
    data?: any, 
    config?: AxiosRequestConfig
  ): Promise<APIResponse<T>> {
    const response = await this.client.put(url, data, config);
    return response.data;
  }

  async patch<T = any>(
    url: string, 
    data?: any, 
    config?: AxiosRequestConfig
  ): Promise<APIResponse<T>> {
    const response = await this.client.patch(url, data, config);
    return response.data;
  }

  async delete<T = any>(
    url: string, 
    config?: AxiosRequestConfig
  ): Promise<APIResponse<T>> {
    const response = await this.client.delete(url, config);
    return response.data;
  }

  // =============================================================================
  // 🔐 AUTHENTICATION METHODS
  // =============================================================================

  setAuthTokens(accessToken: string, refreshToken: string, expiresIn: number): void {
    this.tokenManager.setTokens(accessToken, refreshToken, expiresIn);
  }

  clearAuthTokens(): void {
    this.tokenManager.clearTokens();
  }

  isAuthenticated(): boolean {
    return this.tokenManager.isAuthenticated();
  }

  getAccessToken(): string | null {
    return this.tokenManager.getAccessToken();
  }

  // =============================================================================
  // 📁 FILE UPLOAD
  // =============================================================================

  async uploadFile<T = any>(
    url: string,
    file: File,
    onProgress?: (progress: number) => void,
    additionalData?: Record<string, any>
  ): Promise<APIResponse<T>> {
    const formData = new FormData();
    formData.append('file', file);

    if (additionalData) {
      Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, value);
      });
    }

    const response = await this.client.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = (progressEvent.loaded / progressEvent.total) * 100;
          onProgress(Math.round(progress));
        }
      }
    });

    return response.data;
  }

  // =============================================================================
  // 📥 FILE DOWNLOAD
  // =============================================================================

  async downloadFile(
    url: string,
    filename?: string,
    onProgress?: (progress: number) => void
  ): Promise<void> {
    const response = await this.client.get(url, {
      responseType: 'blob',
      onDownloadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = (progressEvent.loaded / progressEvent.total) * 100;
          onProgress(Math.round(progress));
        }
      }
    });

    // Create download link
    const blob = new Blob([response.data]);
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename || 'download';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(downloadUrl);
  }

  // =============================================================================
  // 🔍 HEALTH CHECK
  // =============================================================================

  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      const response = await this.client.get('/health');
      return response.data;
    } catch (error) {
      throw this.transformError(error as AxiosError);
    }
  }
}

// =============================================================================
// 🌐 WEBSOCKET CLIENT
// =============================================================================

interface WebSocketEventMap {
  'scan:started': { scanId: string; projectId: string };
  'scan:progress': { scanId: string; progress: number; stage: string };
  'scan:completed': { scanId: string; results: any };
  'scan:failed': { scanId: string; error: string };
  'vulnerability:found': { vulnerabilityId: string; scanId: string; severity: string };
  'project:updated': { projectId: string; changes: string[] };
  'notification': { type: string; message: string; data?: any };
}

class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private listeners: Map<string, Set<Function>> = new Map();
  private isConnecting = false;

  constructor(url: string) {
    this.url = url;
  }

  connect(token?: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.CONNECTING)) {
        return;
      }

      this.isConnecting = true;
      const wsUrl = token ? `${this.url}?token=${token}` : this.url;
      
      try {
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          console.log('🔗 WebSocket connected');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
          } catch (error) {
            console.error('❌ Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onclose = (event) => {
          console.log('🔌 WebSocket disconnected', event.code, event.reason);
          this.isConnecting = false;
          this.ws = null;

          if (!event.wasClean && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect();
          }
        };

        this.ws.onerror = (error) => {
          console.error('❌ WebSocket error:', error);
          this.isConnecting = false;
          reject(error);
        };
      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  private scheduleReconnect(): void {
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts);
    this.reconnectAttempts++;

    console.log(`🔄 Scheduling WebSocket reconnect attempt ${this.reconnectAttempts} in ${delay}ms`);
    
    setTimeout(() => {
      this.connect();
    }, delay);
  }

  private handleMessage(data: any): void {
    const { type, payload } = data;
    
    if (this.listeners.has(type)) {
      this.listeners.get(type)?.forEach(callback => {
        try {
          callback(payload);
        } catch (error) {
          console.error(`❌ Error in WebSocket listener for ${type}:`, error);
        }
      });
    }
  }

  on<K extends keyof WebSocketEventMap>(
    event: K, 
    callback: (data: WebSocketEventMap[K]) => void
  ): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)?.add(callback);
  }

  off<K extends keyof WebSocketEventMap>(
    event: K, 
    callback: (data: WebSocketEventMap[K]) => void
  ): void {
    this.listeners.get(event)?.delete(callback);
  }

  emit(event: string, data: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: event, payload: data }));
    }
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
    this.listeners.clear();
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

// =============================================================================
// 🚀 EXPORTS
// =============================================================================

// Create singleton instances
export const httpClient = new HTTPClient();

export const wsClient = new WebSocketClient(
  import.meta.env.VITE_WS_URL || 
  `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`
);

// Export classes for custom instances
export { HTTPClient, WebSocketClient, TokenManager };

// Export types
export type { APIClientConfig, WebSocketEventMap };