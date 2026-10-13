// Bundle entry: re-exports the Marmot client pieces the app uses so the browser
// loads a self-contained file (vendor/marmot.js) with no bare imports.
export { MarmotClient, GroupRumorHistory } from "@internet-privacy/marmot-ts/client";
