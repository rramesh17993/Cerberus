import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { ConfigManager } from './config-manager.js';
import { Logger } from './logger.js';

/**
 * API Client for SecureScan Platform
 * 
 * Provides a typed interface for interacting with the SecureScan backend API.
 * Handles authentication, request/response interceptors, and error handling.
 */

export interface APIClientConfig {
  baseURL?: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface APIError {
  message: string;
  code?: string;
  details?: any;
  statusCode?: number;
}

export class APIClient {
  private client: AxiosInstance;
  private configManager: ConfigManager;
  private logger: Logger;

  constructor(config?: APIClientConfig) {
    this.configManager = new ConfigManager();
    this.logger = new Logger();
    
    this.client = axios.create({
      timeout: config?.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'SecureScan-CLI/1.0.0'
      }
    });

    this.setupInterceptors();
    
    if (config) {
      this.updateConfig(config);
    }
  }

  /**
   * Initialize client with configuration from ConfigManager
   */
  async initialize(): Promise<void> {
    try {
      const config = await this.configManager.getAPIConfig();
      
      if (config.apiUrl) {
        this.client.defaults.baseURL = `${config.apiUrl}/api/v1`;
      }
      
      if (config.apiKey) {
        this.client.defaults.headers.common['Authorization'] = `Bearer ${config.apiKey}`;
      }
    } catch (error) {
      this.logger.warn('Failed to initialize API client with saved config:', error);
    }
  }

  /**
   * Update client configuration
   */
  updateConfig(config: APIClientConfig): void {
    if (config.baseURL) {
      this.client.defaults.baseURL = `${config.baseURL}/api/v1`;
    }
    
    if (config.apiKey) {
      this.client.defaults.headers.common['Authorization'] = `Bearer ${config.apiKey}`;
    }
    
    if (config.timeout) {
      this.client.defaults.timeout = config.timeout;
    }
  }

  /**
   * Test API connectivity and authentication
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.get('/health');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * GET request
   */
  async get<T = any>(url: string, params?: any): Promise<AxiosResponse<T>> {
    await this.initialize();
    return this.client.get(url, { params });
  }

  /**
   * POST request
   */
  async post<T = any>(url: string, data?: any): Promise<AxiosResponse<T>> {
    await this.initialize();
    return this.client.post(url, data);
  }

  /**
   * PUT request
   */
  async put<T = any>(url: string, data?: any): Promise<AxiosResponse<T>> {
    await this.initialize();
    return this.client.put(url, data);
  }

  /**
   * PATCH request
   */
  async patch<T = any>(url: string, data?: any): Promise<AxiosResponse<T>> {
    await this.initialize();
    return this.client.patch(url, data);
  }

  /**
   * DELETE request
   */
  async delete<T = any>(url: string): Promise<AxiosResponse<T>> {
    await this.initialize();
    return this.client.delete(url);
  }

  /**
   * Upload file
   */
  async upload<T = any>(url: string, formData: FormData): Promise<AxiosResponse<T>> {
    await this.initialize();
    return this.client.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
  }

  /**
   * Download file
   */
  async download(url: string, params?: any): Promise<AxiosResponse<Buffer>> {
    await this.initialize();
    return this.client.get(url, {
      params,
      responseType: 'arraybuffer'
    });
  }

  /**
   * Setup request/response interceptors
   */
  private setupInterceptors(): void {
    // Request interceptor for logging
    this.client.interceptors.request.use(
      (config) => {
        this.logger.debug(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
        return config;
      },
      (error) => {
        this.logger.error('API Request Error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => {
        this.logger.debug(`API Response: ${response.status} ${response.config.url}`);
        return response;
      },
      (error) => {
        const apiError = this.handleAPIError(error);
        this.logger.error('API Error:', apiError);
        return Promise.reject(apiError);
      }
    );
  }

  /**
   * Handle and format API errors
   */
  private handleAPIError(error: any): APIError {
    if (error.response) {
      // Server responded with error status
      const { status, data } = error.response;
      return {
        message: data?.message || `HTTP ${status} Error`,
        code: data?.code,
        details: data?.details,
        statusCode: status
      };
    } else if (error.request) {
      // Request was made but no response received
      return {
        message: 'Network error - unable to reach server',
        code: 'NETWORK_ERROR'
      };
    } else {
      // Something else happened
      return {
        message: error.message || 'Unknown error occurred',
        code: 'UNKNOWN_ERROR'
      };
    }
  }

  /**
   * Authentication methods
   */
  auth = {
    /**
     * Login with email and password
     */
    login: async (email: string, password: string) => {
      const response = await this.post('/auth/login', { email, password });
      const { accessToken } = response.data;
      
      // Update authorization header
      this.client.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      
      // Save token to config
      await this.configManager.updateConfig({ apiKey: accessToken });
      
      return response.data;
    },

    /**
     * Login with API key
     */
    loginWithApiKey: async (apiKey: string) => {
      this.client.defaults.headers.common['Authorization'] = `Bearer ${apiKey}`;
      
      // Test the API key
      try {
        await this.get('/auth/me');
        await this.configManager.updateConfig({ apiKey });
        return true;
      } catch {
        delete this.client.defaults.headers.common['Authorization'];
        throw new Error('Invalid API key');
      }
    },

    /**
     * Logout
     */
    logout: async () => {
      try {
        await this.post('/auth/logout');
      } catch {
        // Ignore logout errors
      }
      
      // Clear authorization header
      delete this.client.defaults.headers.common['Authorization'];
      
      // Clear token from config
      await this.configManager.updateConfig({ apiKey: undefined });
    },

    /**
     * Get current user
     */
    getCurrentUser: async () => {
      const response = await this.get('/auth/me');
      return response.data;
    },

    /**
     * Refresh token
     */
    refreshToken: async () => {
      const response = await this.post('/auth/refresh');
      const { accessToken } = response.data;
      
      this.client.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      await this.configManager.updateConfig({ apiKey: accessToken });
      
      return response.data;
    }
  };

  /**
   * Project methods
   */
  projects = {
    /**
     * List projects
     */
    list: async (params?: { page?: number; pageSize?: number; search?: string }) => {
      const response = await this.get<PaginatedResponse<any>>('/projects', params);
      return response.data;
    },

    /**
     * Get project by ID
     */
    get: async (id: string) => {
      const response = await this.get(`/projects/${id}`);
      return response.data;
    },

    /**
     * Create project
     */
    create: async (data: any) => {
      const response = await this.post('/projects', data);
      return response.data;
    },

    /**
     * Update project
     */
    update: async (id: string, data: any) => {
      const response = await this.put(`/projects/${id}`, data);
      return response.data;
    },

    /**
     * Delete project
     */
    delete: async (id: string) => {
      const response = await this.delete(`/projects/${id}`);
      return response.data;
    }
  };

  /**
   * Scan methods
   */
  scans = {
    /**
     * List scans
     */
    list: async (params?: { 
      projectId?: string; 
      status?: string; 
      page?: number; 
      pageSize?: number 
    }) => {
      const response = await this.get<PaginatedResponse<any>>('/scans', params);
      return response.data;
    },

    /**
     * Get scan by ID
     */
    get: async (id: string) => {
      const response = await this.get(`/scans/${id}`);
      return response.data;
    },

    /**
     * Create scan
     */
    create: async (data: any) => {
      const response = await this.post('/scans', data);
      return response.data;
    },

    /**
     * Cancel scan
     */
    cancel: async (id: string) => {
      const response = await this.delete(`/scans/${id}`);
      return response.data;
    },

    /**
     * Get scan results
     */
    getResults: async (id: string, format?: string) => {
      const response = await this.get(`/scans/${id}/results`, { format });
      return response.data;
    },

    /**
     * Download scan report
     */
    downloadReport: async (id: string, format: string = 'pdf') => {
      const response = await this.download(`/scans/${id}/report`, { format });
      return response.data;
    }
  };

  /**
   * Vulnerability methods
   */
  vulnerabilities = {
    /**
     * List vulnerabilities
     */
    list: async (params?: {
      projectId?: string;
      scanId?: string;
      severity?: string[];
      status?: string;
      page?: number;
      pageSize?: number;
    }) => {
      const response = await this.get<PaginatedResponse<any>>('/vulnerabilities', params);
      return response.data;
    },

    /**
     * Get vulnerability by ID
     */
    get: async (id: string) => {
      const response = await this.get(`/vulnerabilities/${id}`);
      return response.data;
    },

    /**
     * Update vulnerability status
     */
    updateStatus: async (id: string, status: string, comment?: string) => {
      const response = await this.patch(`/vulnerabilities/${id}`, {
        status,
        comment
      });
      return response.data;
    },

    /**
     * Bulk update vulnerabilities
     */
    bulkUpdate: async (ids: string[], updates: any) => {
      const response = await this.patch('/vulnerabilities/bulk', {
        ids,
        updates
      });
      return response.data;
    }
  };
}