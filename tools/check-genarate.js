// Regression check for genarate() in src/global/format.js and the explicit-mask
// branch of setcellvalue() in src/global/setdata.js — the fork has no test
// suite, so this bundles both straight from src/ with esbuild and runs them in
// plain node:
//
//     node tools/check-genarate.js
//
// genarate() infers [m, ct, v] from a typed string. An amount like "15,812.91"
// used to come back as v = 15812 under "#,##0.00": the cell showed the cents
// (from m) but held a value without them, and that value is what gets saved
// and printed.
//
// setcellvalue() then decides whether a cell keeps its own mask. A comma
// amount under "0.00" used to take the inferred "#,##0" and lose its decimals
// for good (invoice b92ed772, I49) — and once a cell was "#,##0", typing
// "8163100.00" into it could not bring them back. The editor now widens the
// mask to the typed decimals (maskWidenedToTypedDecimals(), also in setdata.js,
// called from formula.updatecell(), which is too DOM-bound to bundle here).

const fs = require("fs");
const os = require("os");
const path = require("path");
const assert = require("assert");

const root = path.join(__dirname, "..");
const out = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), "check-genarate-")),
  "setdata.js"
);

// [typed, v, fa]
const amounts = [
  ["15,812.91", 15812.91, "#,##0.00"],
  ["434,011.25", 434011.25, "#,##0.00"],
  ["-1,234.56", -1234.56, "#,##0.00"],
  ["12,000.5", 12000.5, "#,##0.0"],
  ["12,000.00", 12000, "#,##0.00"],
  ["12,000", 12000, "#,##0"],
  ["8,163,100.00", 8163100, "#,##0.00"],
  ["8,163,100.75", 8163100.75, "#,##0.00"],
  ["-8,163,100", -8163100, "#,##0"],
  ["1,234.567", 1234.567, "#,##0.000"],
  ["15812.91", 15812.91, "0.00"],
];

// The old pattern left the decimal point unescaped, so any character could
// stand in for it and the string became a NaN "number".
const notNumbers = ["1,234x56", "1,234,56"];

// [cell's mask before, written, fa after, v after, m after]. A null mask is a
// cell with no format at all.
const writes = [
  // A comma amount keeps the mask's decimals and gains the separator.
  ["0.00", "8,163,100", "#,##0.00", 8163100, "8,163,100.00"],
  ["0.00", "15,812.91", "#,##0.00", 15812.91, "15,812.91"],
  ["0.000", "8,163,100", "#,##0.000", 8163100, "8,163,100.000"],
  ["0", "8,163,100", "#,##0", 8163100, "8,163,100"],
  [
    "0.00;[Red](0.00)",
    "-1,234.56",
    "#,##0.00;[Red](#,##0.00)",
    -1234.56,
    "(1,234.56)",
  ],
  // A mask that already has a separator stays exactly as it is.
  [
    "#,##0.00;[Red](#,##0.00)",
    "12,000",
    "#,##0.00;[Red](#,##0.00)",
    12000,
    "12,000.00",
  ],
  // Never hide decimals the user typed: the inferred format wins, as before.
  ["0.00", "1,234.567", "#,##0.000", 1234.567, "1,234.567"],
  ["#,##0", "8,163,100.00", "#,##0.00", 8163100, "8,163,100.00"],
  // Unchanged: a plain number typed into a masked cell keeps the mask.
  ["#,##0", "8163100.00", "#,##0", 8163100, "8,163,100"],
  ["0.00", "8163100.00", "0.00", 8163100, "8163100.00"],
  // Unchanged: no mask, or one that is not a number mask, takes the inference.
  [null, "8,163,100", "#,##0", 8163100, "8,163,100"],
  ["yyyy-MM-dd", "8,163,100", "#,##0", 8163100, "8,163,100"],
  // Unchanged: a placeholder keeps the mask; a percent still wins over it.
  ["0.00", "{freight_amount}", "0.00", "{freight_amount}", "{freight_amount}"],
  ["0.00", "75%", "0%", 0.75, "75%"],
];

// [cell's mask, what the user typed in the editor, mask after]. null means
// the mask stays as it is. maskWidenedToTypedDecimals() is what
// formula.updatecell() applies before it hands the typed value on.
const widenings = [
  ["#,##0", "8163100.00", "#,##0.00"],
  ["#,##0", "15812.91", "#,##0.00"],
  ["0", "8163100.5", "0.0"],
  ["#,##0;[Red](#,##0)", "-1.25", "#,##0.00;[Red](#,##0.00)"],
  ["#,##0.00_);(#,##0.00)", "1.125", "#,##0.000_);(#,##0.000)"],
  // Never narrow, and nothing to do when the mask already shows enough.
  ["0.00", "8163100.00", null],
  ["0.00", "8163100", null],
  ["#,##0.00", "8163100.5", null],
  // Not a plain number: setcellvalue() and genarate() handle these.
  ["#,##0", "8,163,100.00", null],
  ["#,##0", "{freight_amount}", null],
  // Not a plain number mask.
  ["General", "1.50", null],
  ["0%", "0.50", null],
  ["yyyy-MM-dd", "1.50", null],
  ["0.00E+00", "1.234", null],
  ["@", "1.50", null],
];

// format.js imports getdata.js only for valueShowEs(), and getdata.js drags in
// the whole DOM-bound engine (new Image() at load time, …). util.js does the
// same through constant.js, and setdata.js takes only getObjType() from it and
// only `allowUpdate` off the websocket server. Swap all three for stubs; the
// getObjType() stub answers the same names as util.js's lookup table.
const stubs = {
  getdata: "export function getcellvalue() {}",
  util:
    "export function getObjType(obj) {" +
    "  return Object.prototype.toString.call(obj).slice(8, -1).replace(/^[A-Z]/, c => c.toLowerCase())" +
    "}",
  server: "export default { allowUpdate: false }",
};
const stubModules = {
  name: "stub-modules",
  setup(build) {
    build.onResolve({ filter: /\/(getdata|util|server)$/ }, ({ path: p }) => ({
      path: p.split("/").pop(),
      namespace: "stub",
    }));
    build.onLoad({ filter: /.*/, namespace: "stub" }, ({ path: p }) => ({
      contents: stubs[p],
    }));
  },
};

let failed = 0;

function check(label, fn) {
  try {
    fn();
    console.log("ok   " + label);
  } catch (e) {
    failed++;
    console.log(
      "FAIL " + label + "\n     " + e.message.split("\n").join("\n     ")
    );
  }
}

function run() {
  const { genarate, setcellvalue, maskWidenedToTypedDecimals } = require(out);

  for (const [typed, v, fa] of amounts) {
    check("genarate " + JSON.stringify(typed), () => {
      const [m, ct, value] = genarate(typed);
      assert.deepStrictEqual(
        { v: value, fa: ct.fa, t: ct.t },
        { v, fa, t: "n" }
      );
      assert.strictEqual(String(m), typed);
    });
  }

  for (const typed of notNumbers) {
    check("genarate " + JSON.stringify(typed) + " is not a number", () => {
      const [, ct, value] = genarate(typed);
      assert.notStrictEqual(ct.t, "n", "inferred as a number, v = " + value);
    });
  }

  for (const [before, typed, fa, v, m] of writes) {
    const label = JSON.stringify(typed) + " into " + JSON.stringify(before);
    check("setcellvalue " + label, () => {
      // The shape an xlsx text cell arrives in: quote-prefixed, typed as text.
      const cell =
        before == null ? null : { ct: { fa: before, t: "s" }, qp: 1 };
      const d = [[cell]];
      const after = setcellvalue(0, 0, d, typed);
      assert.deepStrictEqual(
        { fa: after.ct.fa, v: after.v, m: String(after.m) },
        { fa, v, m }
      );
    });
  }

  for (const [fa, typed, widened] of widenings) {
    const label = JSON.stringify(typed) + " typed into " + JSON.stringify(fa);
    check("maskWidenedToTypedDecimals " + label, () => {
      assert.strictEqual(maskWidenedToTypedDecimals(fa, typed), widened);
    });
  }

  // I49 on invoice b92ed772 as saved: a number under "#,##0". The editor commit
  // is updatecell() widening the mask, then setcellvalue() with that cell.
  check('editor commit "8163100.00" into I49 (8163100 under "#,##0")', () => {
    const typed = "8163100.00";
    const cell = { ct: { fa: "#,##0", t: "n" }, v: 8163100, m: "8,163,100" };
    const d = [[cell]];
    const curv = JSON.parse(JSON.stringify(cell));
    curv.v = typed;
    curv.ct = { fa: maskWidenedToTypedDecimals(cell.ct.fa, typed), t: "n" };
    const after = setcellvalue(0, 0, d, curv);
    assert.deepStrictEqual(
      { fa: after.ct.fa, v: after.v, m: String(after.m) },
      { fa: "#,##0.00", v: 8163100, m: "8,163,100.00" }
    );
  });

  if (failed) {
    console.log("\n" + failed + " failed");
    process.exit(1);
  }
  console.log("\nall passed");
}

require("esbuild")
  .build({
    stdin: {
      contents:
        "export { genarate } from './src/global/format.js'\n" +
        "export { setcellvalue, maskWidenedToTypedDecimals } from './src/global/setdata.js'",
      resolveDir: root,
    },
    bundle: true,
    platform: "node",
    format: "cjs",
    outfile: out,
    plugins: [stubModules],
    logLevel: "error",
  })
  .then(run, e => {
    console.error(e);
    process.exit(1);
  });
