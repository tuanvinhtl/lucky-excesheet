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
// setcellvalue() then decides whether a cell keeps its own mask. It always
// does: the template's mask says how many decimals a cell shows — 0 to 3 —
// and nothing typed changes that. A comma amount under "0.00" used to take the
// inferred "#,##0" and lose its decimals for good (invoice b92ed772, I49); a
// typed "0.00" once turned a 0dp cell into 2dp for good (1.0.29, Elaine's
// "EXCEL_WS_OVERAGE test dp elaine" on QA).
//
// The same holds for a cell still carrying the xlsx quote prefix (qp): typing
// into one used to make it "@" text holding exactly what was typed, so a 3dp
// quantity took any dp while the 0dp totals under it kept theirs.

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
  ["0.000", "15,812.913", "#,##0.000", 15812.913, "15,812.913"],
  ["0.000", "15,812.91", "#,##0.000", 15812.91, "15,812.910"],
  ["0.000", "15,812.9136", "#,##0.000", 15812.9136, "15,812.914"],
  [
    "0.000;[Red](0.000)",
    "-1,234.567",
    "#,##0.000;[Red](#,##0.000)",
    -1234.567,
    "(1,234.567)",
  ],
  ["0.00", "15,812.913", "#,##0.00", 15812.913, "15,812.91"],
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
  // The mask decides the decimals even when more were typed; the value keeps them.
  ["0.00", "1,234.567", "#,##0.00", 1234.567, "1,234.57"],
  ["#,##0", "8,163,100.00", "#,##0", 8163100, "8,163,100"],
  ["0.0", "8,163,100.00", "#,##0.0", 8163100, "8,163,100.0"],
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

// [template mask, what the user typed, v after, m after] for a cell already
// holding a number — what Edit Invoice opens. The mask after is always the
// template's own (plus a separator when one was typed, see `writes`): 2dp shows
// 2dp, 1dp shows 1dp, 0dp shows 0dp, whatever was typed.
const typedValues = [
  ["0.00", "5", 5, "5.00"],
  ["0.00", "5.5", 5.5, "5.50"],
  ["0.00", "5.123", 5.123, "5.12"],
  ["#,##0.00", "1234.5", 1234.5, "1,234.50"],
  ["0.0", "5", 5, "5.0"],
  ["0.0", "5.24", 5.24, "5.2"],
  ["0.0", "5.00", 5, "5.0"],
  ["0", "5.24", 5.24, "5"],
  ["0", "0.00", 0, "0"],
  ["#,##0", "8163100.00", 8163100, "8,163,100"],
  ["0.000", "5", 5, "5.000"],
  ["0.000", "5.5", 5.5, "5.500"],
  ["0.000", "5.12", 5.12, "5.120"],
  ["0.000", "5.1234", 5.1234, "5.123"],
  ["0.000", "0.00", 0, "0.000"],
  ["#,##0.000", "1234.5", 1234.5, "1,234.500"],
  ["#,##0.000", "8163100.00", 8163100, "8,163,100.000"],
  ["#,##0.000;[Red](#,##0.000)", "-1234.5678", -1234.5678, "(1,234.568)"],
  ["0.00", "5.123", 5.123, "5.12"],
  ["0", "5.123", 5.123, "5"],
];

// [cell before, what the user typed, fa after, v after, m after] for a cell
// that still carries the quote prefix, run the way formula.updatecell() does
// it: on a copy of the cell, with dropQuotePrefix(), into setcellvalue().
// [[$display_all.bl_quantity]] on invoice de80ba21 (QA) is the first shape.
const quantity = {
  ct: { fa: "#,##0.000", t: "n" },
  v: 1045.278,
  m: "1,045.278",
  qp: 1,
};
const prefixedEdits = [
  [quantity, "1045.27", "#,##0.000", 1045.27, "1,045.270"],
  [quantity, "1045.2786", "#,##0.000", 1045.2786, "1,045.279"],
  [quantity, "1045", "#,##0.000", 1045, "1,045.000"],
  [quantity, "1,045.2", "#,##0.000", 1045.2, "1,045.200"],
  [{ ct: { fa: "0", t: "n" }, v: 0, m: "0", qp: 1 }, "1.10", "0", 1.1, "1"],
  [
    { ct: { fa: "0.00", t: "n" }, v: 5, m: "5.00", qp: 1 },
    "5.123",
    "0.00",
    5.123,
    "5.12",
  ],
  // Unchanged: a text cell stays text.
  [
    { ct: { fa: "@", t: "s" }, v: "3,022.465", m: "3,022.465", qp: 1 },
    "3022.5",
    "@",
    "3022.5",
    "3022.5",
  ],
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
  const { genarate, setcellvalue, dropQuotePrefix } = require(out);

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

  for (const [fa, input, v, m] of typedValues) {
    const label = JSON.stringify(input) + " typed into " + JSON.stringify(fa);
    check("setcellvalue " + label, () => {
      const d = [[{ ct: { fa, t: "n" }, v: 0, m: "0" }]];
      const after = setcellvalue(0, 0, d, input);
      assert.deepStrictEqual(
        { fa: after.ct.fa, v: after.v, m: String(after.m) },
        { fa, v, m }
      );
    });
  }

  for (const [before, input, fa, v, m] of prefixedEdits) {
    const label =
      JSON.stringify(input) +
      " typed into quote-prefixed " +
      JSON.stringify(before.ct.fa);
    check("updatecell " + label, () => {
      const d = [[JSON.parse(JSON.stringify(before))]];
      const curv = JSON.parse(JSON.stringify(d[0][0]));
      curv.v = input;
      dropQuotePrefix(curv);
      const after = setcellvalue(0, 0, d, curv);
      assert.deepStrictEqual(
        { fa: after.ct.fa, v: after.v, m: String(after.m) },
        { fa, v, m }
      );
    });
  }

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
        "export { setcellvalue, dropQuotePrefix } from './src/global/setdata.js'",
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
