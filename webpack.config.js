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
        test: /\.ts$/,
        exclude: /node_modules/,
        loader: 'awesome-typescript-loader'
      },
      {
        test: /\.css$/,
        loaders: 'style-loader!css-loader'
      }
    ]
  },
  resolve: {
    extensions: ['*', '.ts', '.js']
  },
  output: {
    path: __dirname + '/client',
    publicPath: '/',
    filename: 'bundle.js'
  },
  plugins: [
    new webpack.HotModuleReplacementPlugin(),
    new webpack.optimize.UglifyJsPlugin()
  ],
  devServer: {
    contentBase: './client',
    hot: true
  }
};