import { describe, expect, it } from "vitest";
import { BundleLayoutError, checkPointedPaths } from "./bundle";
import { externalBytes, MAX_EXTERNAL_BYTES, readExternalData, type ExternalFile } from "./external";
import { sha256Digest } from "./hash";

const file = (overrides: Partial<ExternalFile> = {}): ExternalFile => ({
  path: "data/nhanes/DEMO_L.xpt",
  url: "https://wwwn.cdc.gov/Nchs/Data/Nhanes/Public/2021/DataFiles/DEMO_L.xpt",
  sha256: sha256Digest("demographics"),
  bytes: 4_194_304,
  license: "public-domain",
  ...overrides,
});

const own = ["manifest.json", "paper.md", "claims.json", "code/run", "data/external.json", "data/codebook.csv"];

describe("data/external.json", () => {
  it("names each file by where it goes, the URL of its bytes, their digest, size, and license, and optionally its dataset's DOI", () => {
    const files = [file(), file({ path: "data/nhanes/BMX_L.xpt", url: "https://example.org/BMX_L.xpt", doi: "10.5281/zenodo.1234567" })];
    expect(readExternalData(files, own)).toEqual({ files, issues: null });
    expect(externalBytes(files)).toBe(2 * 4_194_304);
  });

  it("turns away a pointer it couldn't fetch: a DOI alone, a URL that isn't https, or one a parser would have to fix", () => {
    const doiOnly: Partial<ExternalFile> = file({ doi: "10.18112/openneuro.ds000001.v1.0.0" });
    delete doiOnly.url;
    for (const entry of [doiOnly, file({ url: "http://example.org/a.csv" }), file({ url: "https://exa mple.org/a.csv" }), file({ url: "https:example.org" })]) {
      expect(readExternalData([entry], own).issues).not.toBeNull();
    }
    expect(readExternalData([{ ...file(), mirror: "https://example.org" }], own).issues).toEqual([
      expect.objectContaining({ path: "/0", message: expect.stringContaining("mirror") }),
    ]);
  });

  it("keeps every path under data/ and clear of the bundle's own files and of each other", () => {
    const issue = (files: ExternalFile[]) => readExternalData(files, own).issues;
    expect(issue([file({ path: "code/helper.py" })])).toEqual([{ path: "/0/path", message: `"code/helper.py" isn't under data/, where the files a bundle points at go` }]);
    expect(issue([file(), file({ path: "data/codebook.csv" })])).toEqual([{ path: "/1/path", message: `"data/codebook.csv" is both in the bundle and pointed at` }]);
    expect(issue([file(), file()])).toEqual([{ path: "/1/path", message: `"data/nhanes/DEMO_L.xpt" is pointed at twice` }]);
    expect(issue([file({ path: "data/external.json" })])?.[0].path).toBe("/0/path");
    // As a bundle's own paths must, so a mirror on any file system can hold them all.
    expect(issue([file({ path: "data/Codebook.csv" })])).toEqual([{ path: "/0/path", message: `"data/Codebook.csv" and "data/codebook.csv" differ only in case` }]);
    expect(issue([file({ path: "data/a.csv" }), file({ path: "data/A.csv" })])?.[0].path).toBe("/1/path");
    expect(issue([file({ path: "data/codebook.csv/part1.csv" })])?.[0]).toMatchObject({ path: "/0/path", message: expect.stringContaining("both a file and a directory") });
    expect(issue([file({ path: "data/../code/run" })])?.[0]).toMatchObject({ path: "/0/path", message: expect.stringContaining("not a normalized relative path") });
  });

  it("points at no more than any verifier can say it downloads", () => {
    const big = Array.from({ length: 11 }, (_, i) => file({ path: `data/part${i}.bin`, bytes: MAX_EXTERNAL_BYTES / 10 }));
    expect(readExternalData(big, own).issues).toEqual([expect.objectContaining({ path: "", message: expect.stringContaining("10 TB") })]);
    expect(readExternalData(big.slice(0, 10), own).issues).toBeNull();
  });

  it("says which paths are at fault, so a caller can point at the entry", () => {
    expect(() => checkPointedPaths(own, ["data/x.csv", "data/X.csv"])).toThrow(BundleLayoutError);
    try {
      checkPointedPaths(own, ["data/x.csv", "data/X.csv"]);
    } catch (error) {
      expect((error as BundleLayoutError).paths).toEqual(["data/X.csv", "data/x.csv"]);
    }
  });
});
