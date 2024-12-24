const path = require('path');

module.exports = {
  webpack: {
    configure: (webpackConfig) => {
      webpackConfig.resolve.plugins.forEach(plugin => {
        if (plugin.constructor.name === 'ModuleScopePlugin') {
          plugin.allowedPaths.push(path.resolve(__dirname, '../../../../lib'));
        }
      });
      return webpackConfig;
    }
  }
};
