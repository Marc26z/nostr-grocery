/* =========================================================================
 * QR rendering helper.
 *
 * Wraps the tiny `qrcode-generator` library behind one function that returns
 * an SVG string, so the login view can show a `nostrconnect://` code for a
 * mobile signer (Amber, nsec.app, …) to scan. Kept pure so it can be tested.
 * ========================================================================= */

import qrcode from "qrcode-generator";

/**
 * Render `text` as an SVG QR code.
 * @param {string} text
 * @param {{ cellSize?: number, margin?: number, level?: "L"|"M"|"Q"|"H" }} [opts]
 * @returns {string} an <svg> element string
 */
export function qrSvg(text, opts = {}) {
  const { cellSize = 4, margin = 2, level = "M" } = opts;
  const qr = qrcode(0, level);
  qr.addData(String(text));
  qr.make();
  return qr.createSvgTag({ cellSize, margin });
}
