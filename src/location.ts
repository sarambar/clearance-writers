// Copyright 2026 Sarambar
// SPDX-License-Identifier: Apache-2.0

import { containsDisallowedCharacters } from "./codec.js";

/**
 * Azure returns a display location (`Central US`) for an input (`centralus`).
 * Compare only after folding case and removing spaces, underscores, and hyphens.
 * `East US 2` and `eastus2` both become `eastus2`.
 */
export function normalizeAzureLocation(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 64 || containsDisallowedCharacters(trimmed)) {
    return null;
  }
  const folded = trimmed.toLowerCase().replace(/[\s_-]+/g, "");
  if (!/^[a-z0-9]+$/.test(folded)) {
    return null;
  }
  return folded;
}

const DISPLAY_LOCATIONS: Record<string, string> = {
  centralus: "Central US",
  eastus: "East US",
  eastus2: "East US 2",
  westus: "West US",
  westus2: "West US 2",
  westus3: "West US 3",
  northcentralus: "North Central US",
  southcentralus: "South Central US",
  westcentralus: "West Central US",
  uksouth: "UK South",
  ukwest: "UK West",
  northeurope: "North Europe",
  westeurope: "West Europe",
};

export function displayAzureLocation(normalized: string): string {
  return DISPLAY_LOCATIONS[normalized] ?? normalized;
}
