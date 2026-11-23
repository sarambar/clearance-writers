// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

/**
 * Lesson 11. This package does not delete role definitions and does not shell
 * out to az. The validator records the flag shape Azure CLI requires, because
 * `az role definition delete --id` is rejected: the command requires `--name`
 * and `--scope`.
 */
export interface RoleDefinitionDeleteArgs {
  name?: string;
  scope?: string;
  id?: string;
}

export function validateRoleDefinitionDeleteArgs(
  args: RoleDefinitionDeleteArgs,
): { ok: true } | { ok: false; message: string } {
  if (args.id !== undefined) {
    return {
      ok: false,
      message: "the following arguments are required: --name/-n",
    };
  }
  if (args.name === undefined || args.name.trim() === "" || args.scope === undefined || args.scope.trim() === "") {
    return {
      ok: false,
      message: "the following arguments are required: --name/-n and --scope",
    };
  }
  if (!args.scope.startsWith("/subscriptions/") || args.scope.includes("..") || /\s/.test(args.scope)) {
    return { ok: false, message: "--scope must be an ARM scope under /subscriptions/" };
  }
  return { ok: true };
}
