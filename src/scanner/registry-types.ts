/**
 * Type definitions for registry API responses
 */

export interface NpmPackageMetadata {
  name: string;
  version?: string;
  'dist-tags'?: {
    latest: string;
  };
  versions?: Record<string, NpmVersionMetadata>;
  time?: Record<string, string>;
  maintainers?: Array<{ name?: string; email?: string }>;
  repository?: {
    url?: string;
  };
  description?: string;
  license?: string | { type?: string };
}

export interface NpmVersionMetadata {
  version?: string;
  dist?: {
    tarball?: string;
    attestations?: {
      provenance?: {
        predicateType?: string;
      };
      url?: string;
    } | null;
  };
  scripts?: Record<string, string>;
  main?: string;
  maintainers?: Array<{ name?: string; email?: string }>;
}

export interface PypiPackageMetadata {
  info: {
    name?: string;
    version?: string;
    author?: string;
    maintainer?: string;
    summary?: string;
    description?: string;
    license?: string;
    home_page?: string;
    project_urls?: {
      Source?: string;
      Repository?: string;
    };
  };
  releases?: Record<string, PypiReleaseFile[]>;
}

export interface PypiReleaseFile {
  filename?: string;
  packagetype?: string;
  upload_time?: string;
  upload_time_iso_8601?: string;
  provenance_url?: string | null;
  metadata_version?: string;
}

export interface CratesPackageMetadata {
  crate: {
    name?: string;
    newest_version?: string;
    max_stable_version?: string;
    max_version?: string;
    created_at?: string;
    updated_at?: string;
    downloads?: number;
    description?: string;
    license?: string;
    repository?: string;
    homepage?: string;
  };
  versions?: Array<{
    num?: string;
    created_at?: string;
    updated_at?: string;
  }>;
  keywords?: Array<{ id?: string; keyword?: string }>;
}

export interface GoModuleInfo {
  Version?: string;
  Time?: string;
}

export interface RubyGemsPackageMetadata {
  name?: string;
  version?: string;
  info?: string;
  authors?: string;
  description?: string;
  licenses?: string[];
  homepage_uri?: string;
  source_code_uri?: string;
  project_uri?: string;
  downloads?: number;
  dependencies?: {
    runtime?: Array<{
      name?: string;
      requirements?: string;
    }>;
  };
}

export interface RegistryResponse<T> {
  ok: boolean;
  status: number;
  data: T | null;
}
