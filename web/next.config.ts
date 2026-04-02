import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  transpilePackages: [path.resolve(__dirname, "../src")],
  // Turbopack: resolve .js imports to .ts source files
  turbopack: {
    resolveExtensions: [".ts", ".tsx", ".js", ".jsx", ".json"],
  },
  headers: async () => [
    {
      source: "/(.*)",
      headers: [
        { key: "X-Frame-Options", value: "DENY" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        {
          key: "Strict-Transport-Security",
          value: "max-age=63072000; includeSubDomains; preload",
        },
        {
          key: "Content-Security-Policy",
          value:
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none';",
        },
        {
          key: "Permissions-Policy",
          value:
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
        },
      ],
    },
  ],
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
