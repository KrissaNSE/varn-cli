// Minimal typings for the parts of js-yaml 4 that Värn uses (the package ships no types).
declare module "js-yaml" {
  export interface Schema {
    readonly __schema: unique symbol;
  }
  export const CORE_SCHEMA: Schema;
  export const JSON_SCHEMA: Schema;
  export interface LoadOptions {
    filename?: string;
    schema?: Schema;
    json?: boolean;
    maxDepth?: number;
    maxTotalMergeKeys?: number;
  }
  export function load(input: string, options?: LoadOptions): unknown;
  export class YAMLException extends Error {}
}
