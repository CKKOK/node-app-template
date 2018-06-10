const webpack = require('webpack');
const config = require('./config');
const { VueLoaderPlugin } = require('vue-loader');

module.exports = {
  target: 'web',
  mode: config.serverEnv,
  entry: [
    'webpack-hot-middleware/client',
    './client-src/index.js'
  ],
  module: {
    rules: [
      {
        test: /\.vue$/,
        use: 'vue-loader'
      }
    ]
  },
  resolve: {
    extensions: ['*', '.js', '.jsx']
  },
  output: {
    path: __dirname + '/client',
    publicPath: '/',
    filename: 'bundle.js'
  },
  plugins: [
    new webpack.HotModuleReplacementPlugin(),
    new VueLoaderPlugin()
  ],
  devServer: {
    contentBase: './client',
    hot: true
  }
};