/** The reference harness's version. Attestations name the harness that made them, as HARNESS. */
export const HARNESS_VERSION = "0.5.0";
export const HARNESS = `sj-harness ${HARNESS_VERSION}`;
/**
 * What the harness calls itself to every host it asks, as User-Agent. Some data hosts turn away
 * the name Node gives itself, "node" (Zenodo answers 403 to it), so the harness names itself.
 */
export const USER_AGENT = `sj-harness/${HARNESS_VERSION} (+https://sciencejournal.ai)`;
