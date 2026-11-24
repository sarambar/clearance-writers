// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

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
