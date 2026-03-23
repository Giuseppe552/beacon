import { describe, it, expect } from "vitest";
import { EXPOSED_PATHS } from "./paths.js";

describe("EXPOSED_PATHS", () => {
  it("has no duplicate paths", () => {
    const paths = EXPOSED_PATHS.map((p) => p.path);
    const unique = new Set(paths);
    expect(paths.length).toBe(unique.size);
  });

  it("all paths start with /", () => {
    for (const ep of EXPOSED_PATHS) {
      expect(ep.path.startsWith("/")).toBe(true);
    }
  });

  it("all entries have name, severity, and risk", () => {
    for (const ep of EXPOSED_PATHS) {
      expect(ep.name.length).toBeGreaterThan(0);
      expect(ep.risk.length).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low", "info"]).toContain(ep.severity);
    }
  });

  it(".env validator matches KEY=VALUE format", () => {
    const env = EXPOSED_PATHS.find((p) => p.path === "/.env");
    expect(env?.validate).toBeDefined();
    expect(env!.validate!("DB_HOST=localhost\nDB_PASS=secret", "text/plain")).toBe(true);
    expect(env!.validate!("<html>Not Found</html>", "text/html")).toBe(false);
  });

  it(".git/HEAD validator matches ref format", () => {
    const git = EXPOSED_PATHS.find((p) => p.path === "/.git/HEAD");
    expect(git?.validate).toBeDefined();
    expect(git!.validate!("ref: refs/heads/main\n", "text/plain")).toBe(true);
    expect(git!.validate!("<html>404</html>", "text/html")).toBe(false);
  });

  it("phpinfo validator matches PHP output", () => {
    const php = EXPOSED_PATHS.find((p) => p.path === "/phpinfo.php");
    expect(php?.validate).toBeDefined();
    expect(php!.validate!("<h1>PHP Version 8.2.1</h1>", "text/html")).toBe(true);
    expect(php!.validate!("<html>Not found</html>", "text/html")).toBe(false);
  });

  it("security.txt validator matches Contact field", () => {
    const sec = EXPOSED_PATHS.find((p) => p.path === "/.well-known/security.txt");
    expect(sec?.validate).toBeDefined();
    expect(sec!.validate!("Contact: mailto:security@example.com\n", "text/plain")).toBe(true);
    expect(sec!.validate!("<html>404</html>", "text/html")).toBe(false);
  });
});
