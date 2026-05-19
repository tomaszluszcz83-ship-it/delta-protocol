export const DELTA_CLI_EXIT_OK = 0;
export const DELTA_CLI_EXIT_VERIFICATION_FAILED = 1;
export const DELTA_CLI_EXIT_USAGE_ERROR = 2;
export const DELTA_CLI_EXIT_INTERNAL_ERROR = 3;

export type DeltaCliCodeName =
  | "OK"
  | "VERIFICATION_FAILED"
  | "USAGE_ERROR"
  | "INTERNAL_ERROR";

export interface DeltaMachineReadableResult<T> {
  ok: boolean;
  code: number;
  code_name: DeltaCliCodeName;
  profile: string;
  command: string;
  result?: T;
  errors: string[];
  warnings: string[];
}

export function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

export function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

export function usageResult(command: string, usage: string): DeltaMachineReadableResult<null> {
  return {
    ok: false,
    code: DELTA_CLI_EXIT_USAGE_ERROR,
    code_name: "USAGE_ERROR",
    profile: "delta_typescript_cli_json_v2_10_2",
    command,
    result: null,
    errors: [usage],
    warnings: []
  };
}

export function verificationResult<T>(
  command: string,
  ok: boolean,
  result: T,
  errors: string[] = [],
  warnings: string[] = []
): DeltaMachineReadableResult<T> {
  return {
    ok,
    code: ok ? DELTA_CLI_EXIT_OK : DELTA_CLI_EXIT_VERIFICATION_FAILED,
    code_name: ok ? "OK" : "VERIFICATION_FAILED",
    profile: "delta_typescript_cli_json_v2_10_2",
    command,
    result,
    errors,
    warnings
  };
}

export function internalErrorResult(command: string, err: unknown): DeltaMachineReadableResult<null> {
  return {
    ok: false,
    code: DELTA_CLI_EXIT_INTERNAL_ERROR,
    code_name: "INTERNAL_ERROR",
    profile: "delta_typescript_cli_json_v2_10_2",
    command,
    result: null,
    errors: [err instanceof Error ? `${err.name}:${err.message}` : "unknown_internal_error"],
    warnings: []
  };
}
