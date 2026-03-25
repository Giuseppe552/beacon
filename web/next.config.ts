import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  transpilePackages: [path.resolve(__dirname, "../src")],
  // Turbopack: resolve .js imports to .ts source files
  turbopack: {
    resolveExtensions: [".ts", ".tsx", ".js", ".jsx", ".json"],
  },
  // Webpack (production build): same resolution
  webpack: (config) => {
    config.resolve.extensionAlias = {
      ".js": [".ts", ".js"],
      ".mjs": [".mts", ".mjs"],
    };
    // Scanners in ../src/ import node-html-parser, but on Vercel only
    // web/node_modules exists. Tell webpack to also look here.
    config.resolve.modules = [
      ...(config.resolve.modules ?? []),
      path.resolve(__dirname, "node_modules"),
    ];
    return config;
  },
};

export default nextConfig;
