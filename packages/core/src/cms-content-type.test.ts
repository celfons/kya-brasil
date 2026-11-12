/// <reference types="node" /> // test-only: Buffer, node:fs
// The outer content type of a CMS must say SignedData. The differential test against OpenSSL
// (research/differential) found that PKI.js decodes the content whatever the type says.
import "reflect-metadata";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { OID_CMS_SIGNED_DATA, ecnpjResponsibleCpf, signedDataOf, verifyIcpSignature } from "./icp-brasil.js";
import { withCertificates } from "./issuance.js";

const v = JSON.parse(readFileSync(new URL("../../../docs/vectors/self-issued-v1.json", import.meta.url), "utf8"));
const cms = Buffer.from(v.proof.cms, "base64");
const verify = (cmsBase64: string) => verifyIcpSignature({ cmsBase64, challenge: v.proof.text, expectedCnpj: v.credential.principal.cnpj, anchors: v.anchors, now: new Date(v.verify_at) });
// The OID sits at bytes 6 to 14 of the vector: 06 09 2a 86 48 86 f7 0d 01 07 02.
const OID_AT = cms.indexOf(Buffer.from("2a864886f70d010702", "hex"));
const relabelled = (last: number) => {
  const m = Buffer.from(cms);
  m[OID_AT + 8] = last;
  return m.toString("base64");
};

describe("CMS content type", () => {
  it("accepts the vector, whose content type is SignedData", async () => {
    expect(OID_AT).toBe(6);
    expect(signedDataOf(cms).contentInfo.contentType).toBe(OID_CMS_SIGNED_DATA);
    expect((await verify(v.proof.cms)).cnpj).toBe(v.credential.principal.cnpj);
  });

  it("refuses the same bytes under any other content type", async () => {
    for (const last of [1, 3, 6]) {
      const other = relabelled(last);
      await expect(verify(other)).rejects.toMatchObject({ code: "CHALLENGE_FAILED", message: `signature is not a CMS SignedData: content type 1.2.840.113549.1.7.${last} is not SignedData` });
      expect(() => withCertificates(other, [])).toThrow(/is not SignedData/);
      expect(ecnpjResponsibleCpf(other)).toBeNull();
      expect(() => signedDataOf(Buffer.from(other, "base64"))).toThrow(`content type 1.2.840.113549.1.7.${last} is not SignedData`);
    }
  });
});
