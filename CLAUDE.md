# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A fork of Luckysheet (canvas-based online spreadsheet, upstream no longer maintained) renamed to `opswiz-excel` in package.json. The public JS global is still `luckysheet`. Pre-ES-module-era codebase: jQuery-based, no framework, no TypeScript, no test suite.

Fork-specific addition: `luckysheet.create()` in [src/core.js](src/core.js) is gated by `verifyLicenseKeyLocally()` (same file), which decodes a base64 `userId:timestamp:signature` key and checks its age in the browser. A Node-side HMAC counterpart lives in [src/global/license.js](src/global/license.js) (uses `Buffer`/`crypto`, so it cannot run in the browser bundle).

## Commands

```bash
npm install            # gulp CLI also needs to be global: npm install gulp -g
npm run dev            # dev build + browser-sync server on dist/ with watch/reload
npm run build          # bumps patch version, then production build to dist/
npm run prettier       # check formatting
npm run prettier:fix   # fix formatting
```

There are no tests. Commits follow conventional-commit format (commitlint enforced; `npm run commit` runs commitizen).

## Build pipeline (gulpfile.js)

- The core bundle is built by **esbuild** (`core()` task): `src/index.js` → `dist/luckysheet.umd.js` as an IIFE with global name `luckysheet`. The rollup task (`core_rollup`) exists but is not wired into the dev/build tasks, so the `.esm.js`/`.cjs.js` files referenced in package.json are not produced by the current pipeline.
- CSS is concatenated (not imported from JS): `src/plugins/css/*` → `dist/plugins/css/pluginsCss.css`, `src/plugins/*.css` → `dist/plugins/plugins.css`, `src/css/*` + flatpickr theme → `dist/css/luckysheet.css`.
- Vendored third-party libs in `src/plugins/js/` (jquery-ui, html2canvas, spectrum, jstat, etc.) plus jquery/uuid from node_modules are concatenated into `dist/plugins/js/plugin.js`. A host page must load `plugin.js` **before** `luckysheet.umd.js`.
- `src/index.html` and `src/demoData/` are copied to `dist/` and serve as the dev/demo page (`opswizData.js` is fork-specific demo data).
- The dev server proxies `/luckysheet/` to `http://luckysheet.lashuju.com/` for the collaborative-editing demo backend.

Everything in `dist/` is generated — edit only `src/`.

## Architecture

Entry flow: `src/index.js` → `src/core.js` builds the `luckysheet` object (API functions from `src/global/api.js` merged in via `common_extend`), and `luckysheet.create(options)` merges user options over `src/config.js` defaults into `luckysheetConfigsetting`, then runs DOM/event initializers.

- **`src/store/index.js`** — a single mutable global `Store` object (not reactive) imported by nearly every module. Holds all runtime state: sheet data (`luckysheetfile`, `flowdata`), current selection (`luckysheet_select_save`), UI dimensions, drag/copy/filter flags. State changes do not trigger re-render by themselves; after mutating data you must call a refresh function.
- **`src/global/`** — the engine. Key modules: `draw.js` (canvas rendering), `refresh.js` (`jfrefreshgrid` = re-render after data change, `luckysheetrefreshgrid` = re-render on scroll), `formula.js` (formula parsing/execution), `getdata.js`/`setdata.js` (cell value access on `flowdata`), `api.js` (~7k lines; the public API surface mounted onto the `luckysheet` global).
- **`src/controllers/`** — DOM construction and event handling, one module per UI feature (`toolbar.js`, `keyboard.js`, `select.js`, `sheetBar.js`, `formulaBar.js`, `pivotTable.js`, `filter.js`, …). `handler.js` does overall DOM init; `server.js` handles websocket collaborative editing; `sheetmanage.js` handles sheet lifecycle and the 2D-array ↔ `{r,c,v}` celldata conversion.
- **`src/function/`** — built-in spreadsheet function list, implementations, and localized descriptors.
- **`src/methods/get.js` / `set.js`** — getter/setter helpers exposed on the API.
- **`src/locale/`** — i18n (en, es, zh, zh_tw), selected via the `lang` option.
- **`src/expendPlugins/`** — optional plugins (chart, exportXlsx, print) loaded at runtime by `controllers/expendPlugins.js`; their source is copied to `dist/` as static files rather than bundled.

Rendering is canvas-based: the grid is drawn to canvas while editing/selection/menus are DOM overlays positioned on top. Cell data lives in `Store.flowdata` (2D array of cell objects); persisted sheet config lives in the `Store.luckysheetfile` array entries.
