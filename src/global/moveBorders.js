/**
 * The border commands of a sheet once cells have moved: out of one area and into another by a
 * drag or a cut and paste, or out of (or into) this sheet alone when the other end is another
 * sheet.
 *
 * `borderInfo` is not a list of borders but a history of commands, replayed in order to draw
 * them (getBorderInfoComputeRange in border.js). A move used to cut every range command around
 * the cells that left, and a command such as "outside" or "left" means something different on
 * each piece it is cut into: the outline of one box became the outlines of four, and a sheet
 * whose moved cells had no borders at all came out with new lines across it (FELCOR-139).
 *
 * Instead every command stays whole, and on top of them:
 *  - both areas are cleared with one "none", so what leaves takes its borders with it and what
 *    lands starts from nothing — the caller then gives each landed cell the sides it had
 *    before it moved, as it always has;
 *  - "none" also clears the sides of the cells touching the areas, so each of those is given
 *    back the sides it had before, from `before`.
 * Every cell outside the two areas therefore draws exactly what it drew before the move.
 *
 * @param {Array|null} borderInfo  the sheet's config.borderInfo, before the move
 * @param {Object} before          getBorderInfoCompute() of that sheet, before the move
 * @param {Array} areas            [{ row: [r1, r2], column: [c1, c2] }, ...] the cells moved from and to
 * @param {number} rowCount        rows in the sheet
 * @param {number} columnCount     columns in the sheet
 * @returns {Array|null} the borderInfo to save; unchanged when the sheet has no borders
 */
export function borderInfoAfterMove(borderInfo, before, areas, rowCount, columnCount) {
    if (!Array.isArray(borderInfo) || borderInfo.length === 0) {
        return borderInfo;
    }

    const inAnArea = (r, c) => areas.some(({ row, column }) => r >= row[0] && r <= row[1] && c >= column[0] && c <= column[1]);

    // A cell's own entries in either area say nothing any more: the "none" below clears them.
    const next = borderInfo.filter(entry => {
        if (entry.rangeType !== "cell") {
            return true;
        }

        return !inAnArea(entry.value.row_index, entry.value.col_index);
    });

    next.push({
        rangeType: "range",
        borderType: "border-none",
        color: "#000000",
        style: "1",
        range: areas.map(({ row, column }) => ({ row: [row[0], row[1]], column: [column[0], column[1]] })),
    });

    // The cells around each area, in the order they are met; a cell next to both is given back once.
    const around = [];
    const seen = new Set();
    const note = (r, c) => {
        const key = r + "_" + c;

        if (r < 0 || c < 0 || r >= rowCount || c >= columnCount || seen.has(key) || inAnArea(r, c)) {
            return;
        }

        seen.add(key);
        around.push([r, c]);
    };

    for (const { row, column } of areas) {
        for (let c = column[0] - 1; c <= column[1] + 1; c++) {
            note(row[0] - 1, c);
            note(row[1] + 1, c);
        }

        for (let r = row[0]; r <= row[1]; r++) {
            note(r, column[0] - 1);
            note(r, column[1] + 1);
        }
    }

    for (const [r, c] of around) {
        const sides = before && before[r + "_" + c];

        if (!sides || !(sides.l || sides.r || sides.t || sides.b)) {
            continue;
        }

        next.push({
            rangeType: "cell",
            value: { row_index: r, col_index: c, l: sides.l, r: sides.r, t: sides.t, b: sides.b },
        });
    }

    return next;
}
