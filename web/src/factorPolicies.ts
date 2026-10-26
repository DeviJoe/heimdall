export const factorPolicies = {
  none: "Опционально",
  any: "TOTP или passkey",
  totp: "TOTP",
  passkey: "Passkey",
  both: "TOTP и passkey",
};

export function describeFactorPolicies(policies: string[]) {
  const totp = policies.some((p) => p === "totp" || p === "both");
  const passkey = policies.some((p) => p === "passkey" || p === "both");
  if (totp && passkey) return factorPolicies.both;
  if (totp) return factorPolicies.totp;
  if (passkey) return factorPolicies.passkey;
  if (policies.includes("any")) return factorPolicies.any;
  return factorPolicies.none;
}
