import { parse } from "node-html-parser";
import type { Finding, Scanner } from "../types.js";
import { getPrecedent } from "../data/precedents.js";

/** Known external form services that store data on third-party infrastructure. */
const EXTERNAL_FORM_SERVICES: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /docs\.google\.com\/forms|forms\.gle/i, name: "Google Forms" },
  { pattern: /typeform\.com/i, name: "Typeform" },
  { pattern: /jotform\.com/i, name: "JotForm" },
  { pattern: /wufoo\.com/i, name: "Wufoo" },
  { pattern: /formspree\.io/i, name: "Formspree" },
  { pattern: /netlify\.com\/.*form/i, name: "Netlify Forms" },
  { pattern: /airtable\.com/i, name: "Airtable" },
];

/** Sensitive field indicators. */
const SENSITIVE_FIELDS = [
  { pattern: /passport/i, label: "passport" },
  { pattern: /birth.?cert|certificate.*birth/i, label: "birth certificate" },
  { pattern: /ssn|social.?security|national.?insurance|ni.?number/i, label: "national ID number" },
  { pattern: /date.?of.?birth|dob/i, label: "date of birth" },
  { pattern: /upload|file|document|attach/i, label: "file upload" },
];

/** Audit forms for security issues. */
export const formsScanner: Scanner = {
  name: "Form Security",
  category: "forms",
  scan: async (ctx) => {
    const findings: Finding[] = [];
    const root = parse(ctx.html);
    const forms = root.querySelectorAll("form");
    const fullText = ctx.html;

    // Check for external form service links/embeds
    for (const svc of EXTERNAL_FORM_SERVICES) {
      if (svc.pattern.test(fullText)) {
        const isGoogle = svc.name === "Google Forms";
        findings.push({
          id: `forms-external-${svc.name.toLowerCase().replace(/\s/g, "-")}`,
          category: "forms",
          severity: isGoogle ? "high" : "medium",
          title: `External form service: ${svc.name}`,
          detail: `${svc.name} detected in page content. Client data submitted through this form is stored on ${svc.name}'s infrastructure.`,
          risk: isGoogle
            ? "Documents uploaded via Google Forms are stored in the form creator's Google Drive under Google's Terms of Service. For passport copies and birth certificates, this means identity documents are stored on consumer cloud infrastructure."
            : `Data submitted to ${svc.name} is stored on their servers under their terms of service. The business has limited control over data retention and access.`,
          precedent: getPrecedent(`forms-external-${svc.name.toLowerCase().replace(/\s/g, "-")}`),
          remediation: `Use a self-hosted form that submits directly to your own server over HTTPS.`,
        });
      }
    }

    // Check for WhatsApp links (common in immigration agencies)
    if (/wa\.me|whatsapp\.com|api\.whatsapp/i.test(fullText)) {
      findings.push({
        id: "forms-whatsapp-communication",
        category: "forms",
        severity: "high",
        title: "WhatsApp used for client communication",
        detail: "WhatsApp link detected. Clients may share documents via WhatsApp.",
        risk: "WhatsApp stores messages and media on Meta's infrastructure. Backups (Google Drive/iCloud) are often unencrypted. No audit trail, no access controls, no guaranteed deletion.",
        precedent: getPrecedent("forms-whatsapp-communication"),
        remediation: "Use encrypted channels designed for sensitive document exchange. Not consumer messaging apps.",
      });
    }

    // Analyse each form element
    for (const form of forms) {
      const action = form.getAttribute("action") ?? "";
      const method = (form.getAttribute("method") ?? "GET").toUpperCase();
      const inputs = form.querySelectorAll("input, textarea, select");
      const inputNames = inputs
        .map((el) =>
          el.getAttribute("name") ??
          el.getAttribute("id") ??
          el.getAttribute("placeholder") ?? "",
        )
        .filter(Boolean);

      // Check if form submits over HTTP (not HTTPS)
      if (action.startsWith("http://")) {
        findings.push({
          id: "forms-http-action",
          category: "forms",
          severity: "critical",
          title: "Form submits over HTTP (unencrypted)",
          detail: `Form action: ${action}`,
          risk: "Data submitted through this form travels in plaintext. Passport copies, names, addresses — all visible to anyone on the network.",
          remediation: "Change the form action to HTTPS.",
        });
      }

      // Check if form uses GET for sensitive data
      if (method === "GET" && inputNames.length > 2) {
        findings.push({
          id: "forms-get-method",
          category: "forms",
          severity: "medium",
          title: "Form uses GET method",
          detail: "Form data will appear in the URL, browser history, server logs, and referrer headers.",
          risk: "Personal information visible in URLs. Shared links expose submitted data.",
          remediation: "Use POST method for forms that collect personal data.",
        });
      }

      // Check for file uploads
      const fileInputs = inputs.filter(
        (el) => el.getAttribute("type") === "file",
      );
      if (fileInputs.length > 0 && !action.startsWith("https://")) {
        findings.push({
          id: "forms-file-upload-insecure",
          category: "forms",
          severity: "high",
          title: "File upload without guaranteed encryption",
          detail: "File upload input found. The form action does not explicitly use HTTPS.",
          risk: "Uploaded documents (passport copies, certificates) may travel unencrypted.",
          remediation: "Ensure file upload forms submit to an HTTPS endpoint.",
        });
      }

      // Check for sensitive fields
      const allFieldText = inputNames.join(" ");
      for (const sf of SENSITIVE_FIELDS) {
        if (sf.pattern.test(allFieldText)) {
          findings.push({
            id: `forms-sensitive-field-${sf.label.replace(/\s/g, "-")}`,
            category: "forms",
            severity: "info",
            title: `Collects sensitive data: ${sf.label}`,
            detail: `Form appears to collect ${sf.label} information.`,
            risk: `${sf.label} data requires careful handling. Check that storage, access controls, and deletion policies are adequate.`,
          });
          break; // one finding per form is enough
        }
      }
    }

    return findings;
  },
};
