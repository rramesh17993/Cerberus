/**
 * 📊 Dashboard Page - Main overview dashboard
 */

import React from 'react';

const DashboardPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Security Dashboard
        </h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Metrics Cards */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
            Total Projects
          </h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">24</p>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
            Active Scans
          </h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">3</p>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
            Critical Issues
          </h3>
          <p className="text-2xl font-bold text-red-600 dark:text-red-400">12</p>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
            Resolved Today
          </h3>
          <p className="text-2xl font-bold text-green-600 dark:text-green-400">8</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Recent Scans
          </h2>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600 dark:text-gray-400">Project Alpha</span>
              <span className="px-2 py-1 text-xs bg-green-100 text-green-800 rounded">Completed</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600 dark:text-gray-400">Project Beta</span>
              <span className="px-2 py-1 text-xs bg-yellow-100 text-yellow-800 rounded">Running</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600 dark:text-gray-400">Project Gamma</span>
              <span className="px-2 py-1 text-xs bg-red-100 text-red-800 rounded">Failed</span>
            </div>
          </div>
        </div>

        {/* Vulnerability Trends */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Vulnerability Trends
          </h2>
          <div className="text-sm text-gray-600 dark:text-gray-400">
            Chart placeholder - Vulnerability trends over time
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;