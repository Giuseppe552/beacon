/**
 * Industry context profiles.
 *
 * Each profile adjusts how findings are interpreted, which precedents
 * are surfaced first, and what risk text is shown. An immigration agency
 * with Hotjar is in a fundamentally different situation than a restaurant.
 */

export type Industry = "immigration" | "law" | "accounting" | "healthcare" | "general";

export type IndustryProfile = {
  name: string;
  /** What kind of data this industry handles — shown in reports. */
  dataDescription: string;
  /** Finding IDs that get severity bumped for this industry. */
  severityBumps: Record<string, "critical" | "high">;
  /** Breach categories to prefer when multiple precedents match. */
  preferredPrecedentCategories: string[];
  /** Extra risk text appended to findings when this industry is active. */
  riskSuffix: Record<string, string>;
};

export const INDUSTRY_PROFILES: Record<Industry, IndustryProfile> = {
  immigration: {
    name: "Immigration Agency",
    dataDescription: "passport copies, birth certificates, visa applications, financial records, biometric data",
    severityBumps: {
      "dns-no-dmarc": "critical",
      "dns-no-spf": "critical",
      "dns-dmarc-none": "critical",
      "third-party-hotjar": "critical",
      "third-party-fullstory": "critical",
      "third-party-microsoft-clarity": "critical",
      "third-party-mouseflow": "critical",
      "third-party-smartlook": "critical",
      "forms-external-google-forms": "critical",
      "forms-whatsapp-communication": "high",
      "cookies-insecure": "high",
    },
    preferredPrecedentCategories: ["legal-professional", "email-spoofing"],
    riskSuffix: {
      "dns-no-dmarc": "Immigration agencies send payment instructions and case updates by email. Without DMARC, an attacker can send your clients a fake invoice that looks identical to yours. UK solicitors lost over £150 million to this exact attack between 2022 and 2024.",
      "dns-no-spf": "Without SPF, anyone on the internet can send an email that appears to come from your domain. Your clients — who trust you with their passport — cannot tell the difference.",
      "third-party-hotjar": "Hotjar records every mouse movement, click, and form interaction on your site. If clients fill in passport numbers, dates of birth, or upload documents, those interactions are captured and stored on Hotjar's servers. This is a GDPR Article 32 failure for a business handling identity documents.",
      "third-party-fullstory": "FullStory captures full session recordings including form input. If clients enter personal data on your site, FullStory's employees can watch the recording. For a business handling passport copies and visa applications, this is a data protection violation.",
      "third-party-microsoft-clarity": "Microsoft Clarity records user sessions including form interactions. If clients enter sensitive personal data, those sessions are captured and stored on Microsoft's infrastructure.",
      "third-party-mouseflow": "Mouseflow records user sessions including form interactions. Sensitive client data entered on your forms is captured and stored on third-party servers.",
      "third-party-smartlook": "Smartlook records user sessions. Any personal data your clients enter — passport numbers, addresses, financial details — is captured and stored on Smartlook's servers.",
      "forms-external-google-forms": "Passport copies and birth certificates submitted through Google Forms are stored on Google's consumer cloud infrastructure, under Google's Terms of Service, not yours. You have no control over retention, no audit trail, and no way to guarantee deletion. The ICO expects organisations handling identity documents to use appropriate technical measures — consumer tools do not meet that standard.",
      "forms-whatsapp-communication": "WhatsApp provides no audit trail, no access controls, and no guaranteed deletion. If a client sends their passport scan via WhatsApp, that image exists on Facebook's servers, on every device in the chat, and in every cloud backup. The FCA fined financial firms over $2 billion for using WhatsApp for business communications.",
      "cookies-insecure": "If your site has a client portal where people check their case status, an insecure session cookie means an attacker who intercepts it can log in as that client — seeing their documents, case details, and personal information.",
    },
  },
  law: {
    name: "Law Firm",
    dataDescription: "court bundles, witness statements, case files, client financial records, legal privilege material",
    severityBumps: {
      "dns-no-dmarc": "critical",
      "dns-no-spf": "critical",
      "dns-dmarc-none": "critical",
      "third-party-hotjar": "high",
      "third-party-fullstory": "high",
      "forms-external-google-forms": "high",
      "forms-whatsapp-communication": "high",
      "cookies-insecure": "high",
    },
    preferredPrecedentCategories: ["legal-professional", "email-spoofing"],
    riskSuffix: {
      "dns-no-dmarc": "Law firms are the number one target for business email compromise. Attackers monitor email chains for ongoing property transactions, then send clients a 'change of bank details' notice at the exact moment a completion payment is due. UK solicitors lost over £150 million to this attack. DPP Law had 32GB of case files — including child abuse allegations — published on the dark web after a breach through one forgotten admin account.",
      "dns-no-spf": "Without SPF, an attacker can send emails that appear to come from your firm. For a practice that sends wire transfer instructions, this is the difference between a spam problem and a six-figure theft.",
      "cookies-insecure": "An insecure session cookie on a client portal means an attacker can access case files, witness statements, and legal privilege material. Tuckers Solicitors had 972,191 files encrypted and 60 court bundles — including rape and murder cases — posted on the dark web.",
    },
  },
  accounting: {
    name: "Accounting Firm",
    dataDescription: "tax returns, SSNs/NI numbers, bank account details, financial statements, payroll data",
    severityBumps: {
      "dns-no-dmarc": "critical",
      "dns-no-spf": "critical",
      "paths-env": "critical",
      "paths-backup-sql": "critical",
      "cookies-insecure": "high",
    },
    preferredPrecedentCategories: ["credential-theft", "email-spoofing", "exposed-files"],
    riskSuffix: {
      "dns-no-dmarc": "Accounting firms handle tax returns, bank account details, and SSNs. Business email compromise targeting accountants often impersonates a client requesting a 'wire transfer for a closing' or an 'urgent tax payment.' A Georgia CPA firm paid $450,000 in ransom after a single employee clicked one link.",
      "paths-env": "An exposed .env file on an accounting firm's server likely contains database credentials. That database contains every client's tax returns, bank account numbers, and SSNs. This is not a theoretical risk — it's the keys to everything.",
      "paths-backup-sql": "A database backup on an accounting firm's server contains the financial lives of every client. Tax returns, bank accounts, SSNs, payroll data. If this file is accessible, the damage is immediate and total.",
    },
  },
  healthcare: {
    name: "Healthcare Provider",
    dataDescription: "patient records, medical histories, insurance data, prescription information",
    severityBumps: {
      "dns-no-dmarc": "critical",
      "third-party-hotjar": "critical",
      "third-party-fullstory": "critical",
      "forms-external-google-forms": "critical",
      "cookies-insecure": "high",
    },
    preferredPrecedentCategories: ["session-recording", "legal-professional"],
    riskSuffix: {
      "third-party-hotjar": "Hotjar records form interactions. If patients enter symptoms, conditions, or medication details on your site, those recordings are stored on Hotjar's servers. This is a direct violation of patient data protection obligations.",
      "forms-external-google-forms": "Patient intake forms on Google Forms mean medical histories are stored on Google's consumer infrastructure. This fails basic healthcare data protection requirements.",
    },
  },
  general: {
    name: "Business",
    dataDescription: "customer data, payment information, personal details",
    severityBumps: {},
    preferredPrecedentCategories: [],
    riskSuffix: {},
  },
};
