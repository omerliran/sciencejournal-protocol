import { describe, expect, it } from "vitest";
import { digestBundle, digestEvidence } from "./bundle";
import { sha256Digest } from "./hash";
import { namedFiles, servedFilesProblem, withdrawnBundle } from "./mirror";

const text = (words: string) => new TextEncoder().encode(words);
const bundle = digestBundle(new Map([["paper.md", text("# Primes\n")], ["claims.json", text("[]\n")], ["signature", text("sig")]]));
const evidence = digestEvidence(new Map([["report.md", text("It holds.")]]));
const other = sha256Digest("another bundle");

describe("what an entry names that has files", () => {
  it("is a bundle's hash, or the digest of an entry's evidence", () => {
    expect(namedFiles({ type: "bundle", bundle: bundle.bundle })).toEqual({ kind: "bundle", digest: bundle.bundle });
    expect(namedFiles({ type: "attestation", bundle: other, evidence: evidence.evidence })).toEqual({ kind: "evidence", digest: evidence.evidence });
    expect(namedFiles({ type: "goal_check", evidence: evidence.evidence })).toEqual({ kind: "evidence", digest: evidence.evidence });
    expect(namedFiles({ type: "canary", bundle: other })).toBeNull();
    expect(namedFiles({ type: "withdrawal", bundle: other })).toBeNull();
  });

  it("names the bundle a withdrawal takes down", () => {
    expect(withdrawnBundle({ type: "withdrawal", bundle: other, reason: "copyright" })).toBe(other);
    expect(withdrawnBundle({ type: "bundle", bundle: other })).toBeNull();
  });
});

describe("checking the files a node serves for an entry", () => {
  const bundleEntry = { type: "bundle", bundle: bundle.bundle };
  const attestation = { type: "attestation", bundle: bundle.bundle, evidence: evidence.evidence };

  it("passes files that hash to what the entry names, every file of a bundle but its signature counting", () => {
    expect(servedFilesProblem({ index: 4, bundle: bundle.bundle, files: bundle.files }, bundleEntry)).toBeNull();
    expect(servedFilesProblem({ index: 5, bundle: bundle.bundle, files: evidence.files }, attestation)).toBeNull();
    // The signature isn't part of the bundle hash, so another one still matches it; the file itself is checked by its digest.
    expect(servedFilesProblem({ index: 4, bundle: bundle.bundle, files: { ...bundle.files, signature: sha256Digest("other") } }, bundleEntry)).toBeNull();
  });

  it("refuses files that hash to something else, or a path the protocol refuses", () => {
    expect(servedFilesProblem({ index: 4, bundle: bundle.bundle, files: { ...bundle.files, "paper.md": sha256Digest("x") } }, bundleEntry)).toContain("hash to");
    expect(servedFilesProblem({ index: 5, bundle: bundle.bundle, files: { ...evidence.files, "../escape": sha256Digest("x") } }, attestation)).toContain("refuses");
    expect(servedFilesProblem({ index: 4, bundle: bundle.bundle, files: { "notes/x.md": sha256Digest("x") } }, bundleEntry)).toContain("refuses");
  });

  it("refuses files said to go with another bundle than the entry names, or served for an entry that names none", () => {
    expect(servedFilesProblem({ index: 5, bundle: other, files: evidence.files }, attestation)).toContain(`but the entry names ${bundle.bundle}`);
    expect(servedFilesProblem({ index: 5, files: evidence.files }, attestation)).toContain("bundle none");
    expect(servedFilesProblem({ index: 6, files: {} }, { type: "idea", text: other })).toContain("names no files");
  });

  it("takes the node's word for the bundle a challenge's evidence goes with, since a challenge names a claim", () => {
    const challenge = { type: "challenge", claim: `claim:${"c".repeat(64)}`, evidence: evidence.evidence };
    expect(servedFilesProblem({ index: 7, bundle: other, files: evidence.files }, challenge)).toBeNull();
  });

  it("checks files listed by digest alone only for which bundle they go with", () => {
    expect(servedFilesProblem({ index: 5, bundle: bundle.bundle, digests: [sha256Digest("x")] }, attestation)).toBeNull();
    expect(servedFilesProblem({ index: 5, bundle: other, digests: [sha256Digest("x")] }, attestation)).toContain("go with bundle");
  });
});
