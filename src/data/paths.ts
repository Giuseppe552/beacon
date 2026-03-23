/**
 * Common paths that should not be publicly accessible.
 * Each entry has a path, what it means if exposed, and how to validate
 * that a 200 response is genuine (not a SPA catch-all).
 */
export type ExposedPath = {
  path: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** What this file/path contains if exposed. */
  risk: string;
  /** How to confirm a 200 is genuine, not a SPA fallback. */
  validate?: (body: string, contentType: string) => boolean;
};

export const EXPOSED_PATHS: ExposedPath[] = [
  // --- Secrets & config ---
  {
    path: "/.env",
    name: "Environment variables",
    severity: "critical",
    risk: "Database credentials, API keys, secrets. Full system compromise.",
    validate: (body) => /^[A-Z_]+=.+/m.test(body),
  },
  {
    path: "/.env.local",
    name: "Local environment overrides",
    severity: "critical",
    risk: "Same as .env — often contains production secrets.",
    validate: (body) => /^[A-Z_]+=.+/m.test(body),
  },
  {
    path: "/.env.production",
    name: "Production environment",
    severity: "critical",
    risk: "Production database URLs, payment keys, auth secrets.",
    validate: (body) => /^[A-Z_]+=.+/m.test(body),
  },

  // --- Source control ---
  {
    path: "/.git/HEAD",
    name: "Git repository",
    severity: "critical",
    risk: "Entire source code, commit history, and embedded secrets recoverable.",
    validate: (body) => body.trimStart().startsWith("ref: refs/"),
  },
  {
    path: "/.git/config",
    name: "Git config",
    severity: "critical",
    risk: "Remote URLs, potentially credentials, branch structure.",
    validate: (body) => body.includes("[core]") || body.includes("[remote"),
  },
  {
    path: "/.svn/entries",
    name: "SVN repository",
    severity: "high",
    risk: "Source code and file structure exposed via Subversion metadata.",
    validate: (body) => /^\d+/.test(body.trim()),
  },

  // --- Config files ---
  {
    path: "/package.json",
    name: "Node.js package manifest",
    severity: "medium",
    risk: "Dependency list, scripts, internal project structure. Attackers use this to find vulnerable dependencies.",
    validate: (body, ct) => ct.includes("json") && body.includes('"dependencies"'),
  },
  {
    path: "/composer.json",
    name: "PHP Composer manifest",
    severity: "medium",
    risk: "PHP dependency list and autoload config.",
    validate: (body, ct) => ct.includes("json") && body.includes('"require"'),
  },
  {
    path: "/wp-config.php.bak",
    name: "WordPress config backup",
    severity: "critical",
    risk: "Database host, username, password, auth keys in plaintext.",
    validate: (body) => body.includes("DB_PASSWORD") || body.includes("DB_HOST"),
  },
  {
    path: "/docker-compose.yml",
    name: "Docker Compose config",
    severity: "high",
    risk: "Service architecture, internal ports, database credentials, volume mounts.",
    validate: (body) => body.includes("services:") || body.includes("version:"),
  },

  // --- Database dumps ---
  {
    path: "/backup.sql",
    name: "Database dump",
    severity: "critical",
    risk: "Full database contents — user records, credentials, business data.",
    validate: (body) =>
      body.includes("CREATE TABLE") || body.includes("INSERT INTO"),
  },
  {
    path: "/dump.sql",
    name: "Database dump",
    severity: "critical",
    risk: "Full database contents.",
    validate: (body) =>
      body.includes("CREATE TABLE") || body.includes("INSERT INTO"),
  },

  // --- Server info ---
  {
    path: "/phpinfo.php",
    name: "PHP info page",
    severity: "high",
    risk: "PHP version, loaded modules, server paths, environment variables. Detailed attack surface map.",
    validate: (body) => body.includes("phpinfo()") || body.includes("PHP Version"),
  },
  {
    path: "/server-status",
    name: "Apache server status",
    severity: "medium",
    risk: "Active connections, client IPs, request URLs. Information useful for timing attacks.",
    validate: (body) => body.includes("Apache Server Status") || body.includes("Scoreboard"),
  },

  // --- Admin panels ---
  {
    path: "/wp-admin/",
    name: "WordPress admin",
    severity: "low",
    risk: "WordPress admin panel accessible. Not a vulnerability itself but confirms WordPress and enables brute-force attempts.",
    validate: (body) => body.includes("wp-login") || body.includes("WordPress"),
  },
  {
    path: "/wp-login.php",
    name: "WordPress login",
    severity: "low",
    risk: "WordPress login page exposed. Enables credential stuffing and brute-force.",
    validate: (body) => body.includes("wp-login") || body.includes("log in"),
  },
  {
    path: "/admin/",
    name: "Admin panel",
    severity: "medium",
    risk: "Administrative interface accessible without authentication or IP restriction.",
    validate: (body) =>
      body.includes("login") || body.includes("password") || body.includes("admin") &&
      !body.includes("<!doctype html>") || body.length < 5000,
  },
  {
    path: "/phpmyadmin/",
    name: "phpMyAdmin",
    severity: "high",
    risk: "Database management tool publicly accessible. Common target for automated attacks.",
    validate: (body) => body.includes("phpMyAdmin") || body.includes("pma_"),
  },

  // --- API docs ---
  {
    path: "/graphql",
    name: "GraphQL endpoint",
    severity: "medium",
    risk: "GraphQL API may allow introspection queries that reveal the entire schema — every table, field, and relationship.",
    validate: (body, ct) => ct.includes("json") || body.includes("graphql"),
  },
  {
    path: "/swagger.json",
    name: "Swagger/OpenAPI spec",
    severity: "medium",
    risk: "Full API documentation including all endpoints, parameters, and response schemas.",
    validate: (body) => body.includes('"swagger"') || body.includes('"openapi"'),
  },
  {
    path: "/api-docs",
    name: "API documentation",
    severity: "medium",
    risk: "API documentation publicly accessible.",
    validate: (body) => body.includes("swagger") || body.includes("openapi"),
  },

  // --- Debug ---
  {
    path: "/debug/vars",
    name: "Go debug variables",
    severity: "high",
    risk: "Runtime variables, memory stats, internal state. Common in Go services.",
    validate: (body, ct) => ct.includes("json"),
  },
  {
    path: "/actuator/health",
    name: "Spring Boot actuator",
    severity: "medium",
    risk: "Application health info. Other actuator endpoints may expose env vars, heap dumps, thread dumps.",
    validate: (body) => body.includes('"status"'),
  },

  // --- Standards ---
  {
    path: "/.well-known/security.txt",
    name: "Security contact (RFC 9116)",
    severity: "info",
    risk: "Not a vulnerability — presence indicates the organisation has a security contact. Absence means no responsible disclosure path.",
    validate: (body) => body.includes("Contact:"),
  },
];
