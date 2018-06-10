const webpack = require('webpack');
const config = require('./config');

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
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: ['babel-loader']
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
    new webpack.HotModuleReplacementPlugin()
  ],
  devServer: {
    contentBase: './client',
    hot: true
  }
};