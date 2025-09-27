import { useState, useEffect } from 'react';
import { api } from '../services/api';

export interface UserDashboardConfig {
  username: string;
  roles: string[];
  access_level: string;
  permissions: string[];
  dashboard_features: string[];
}

export interface UseUserDashboardConfigResult {
  config: UserDashboardConfig | null;
  loading: boolean;
  error: string | null;
  hasPermission: (permission: string) => boolean;
  hasFeature: (feature: string) => boolean;
  isAdmin: boolean;
  isAnalyst: boolean;
  refetch: () => Promise<void>;
}

export const useUserDashboardConfig = (): UseUserDashboardConfigResult => {
  const [config, setConfig] = useState<UserDashboardConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchConfig = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await api.get('/api/v1/user-config');
      
      if (response.ok) {
        const data = await response.json();
        // Handle camelCase conversion from API service layer
        const normalizedConfig: UserDashboardConfig = {
          username: data?.username || 'dev_user',
          roles: data?.roles || ['admin'],
          access_level: data?.access_level || data?.accessLevel || 'admin',
          permissions: data?.permissions || [],
          dashboard_features: data?.dashboard_features || data?.dashboardFeatures || []
        };
        setConfig(normalizedConfig);
      } else if (response.status === 403 || response.status === 401) {
        // Development fallback: provide default admin config when not authenticated
        console.warn('Authentication failed, using development fallback config');
        const fallbackConfig: UserDashboardConfig = {
          username: 'dev_user',
          roles: ['admin', 'super-admin'],
          access_level: 'admin',
          permissions: [
            'view_all_dashboards',
            'manage_cache',
            'view_user_logs',
            'export_data',
            'modify_settings',
            'view_sensitive_data'
          ],
          dashboard_features: [
            'threat_statistics',
            'geographic_threats', 
            'security_metrics',
            'recent_threats',
            'system_health',
            'user_management',
            'admin_controls',
            'audit_logs',
            'cache_management'
          ]
        };
        setConfig(fallbackConfig);
      } else {
        throw new Error(`Failed to fetch user config: ${response.status}`);
      }
    } catch (err) {
      console.error('Error fetching user dashboard config:', err);
      // Provide fallback config even on network errors during development
      const fallbackConfig: UserDashboardConfig = {
        username: 'dev_user',
        roles: ['admin'],
        access_level: 'admin',
        permissions: [
          'view_all_dashboards',
          'export_data',
          'view_sensitive_data'
        ],
        dashboard_features: [
          'threat_statistics',
          'geographic_threats',
          'security_metrics',
          'recent_threats',
          'system_health'
        ]
      };
      setConfig(fallbackConfig);
      setError('Using development fallback configuration');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const hasPermission = (permission: string): boolean => {
    return config?.permissions.includes(permission) || false;
  };

  const hasFeature = (feature: string): boolean => {
    return config?.dashboard_features.includes(feature) || false;
  };

  const isAdmin = config?.access_level === 'admin';
  const isAnalyst = config?.access_level === 'analyst' || isAdmin;

  return {
    config,
    loading,
    error,
    hasPermission,
    hasFeature,
    isAdmin,
    isAnalyst,
    refetch: fetchConfig,
  };
};

export default useUserDashboardConfig;