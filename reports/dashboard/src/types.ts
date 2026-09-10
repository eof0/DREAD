export type HistoryRun = {
  id: string;
  run_id?: string;
  target?: string;
  generated_at?: string;
  total_findings?: number;
  risk_level?: string;
};

export type SuiteReport = {
  reports_schema_version?: string;
  suite?: string;
  report_type?: string;
  title?: string;
  run_id?: string;
  generated_at?: string;
  target?: string;
  sources?: {
    probe?: { included?: boolean; scans?: unknown[] };
    scope?: { included?: boolean; summary?: Record<string, unknown> };
  };
  rollups?: {
    total_findings?: number;
    findings_by_severity?: Record<string, number>;
    findings_by_plugin?: Record<string, number>;
  };
  statistics?: {
    total_findings?: number;
    risk?: { normalized_score?: number; level?: string };
  };
  findings?: NormalizedFinding[];
};

export type Product = {
  cli: string;
  name: string;
  summary: string;
  status: string;
};

export type JobSummary = {
  id: string;
  kind?: string;
  status: string;
  target?: string;
  tool?: string;
  mode?: string;
  return_code?: number;
  has_report?: boolean;
  report_id?: string;
  error?: string;
};

export type JobEvent = {
  type: string;
  message?: string;
  status?: string;
  command?: string[];
  report_id?: string;
  return_code?: number;
  error?: string;
};

export type CannonInstall = {
  manager: string | null;
  package?: string;
  available: boolean;
  command: string | null;
};

export type CannonTool = {
  name: string;
  binary: string;
  category: string;
  description: string;
  available: boolean;
  path: string | null;
  install?: CannonInstall;
};

export type NormalizedFinding = {
  id?: string;
  source_product?: string;
  severity?: string;
  title?: string;
  url?: string;
  plugin_name?: string;
  description?: string;
  remediation?: string;
  evidence?: Record<string, unknown>;
  endpoint_count?: number;
  affected_endpoints?: string[];
  risk_score?: number;
};
