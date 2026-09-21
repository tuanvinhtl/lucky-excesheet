/**
 * Borders when cells move: out of one area and into another by a drag or a cut and paste, or
 * out of (or into) this sheet alone when the other end is another sheet (FELCOR-139).
 *
 * `borderInfo` is not a list of borders but a history of commands, replayed in order to draw
 * them (getBorderInfoComputeRange in border.js). A move used to cut every range command around
 * the cells that left, and a command such as "outside" or "left" means something else on each
 * piece it is cut into: the outline of one box became the outlines of four, and cells with no
 * borders at all, moved out of a bordered table, left new lines across it.
 *
 * Now every command stays whole, and the move is written on top of them, as Excel moves cells:
 *  - both areas are cleared with one "none", so what leaves takes its borders with it and what
 *    lands starts from nothing;
 *  - "none" also clears the side each cell around the areas has facing them, so that side is
 *    given back — but only when it is the cell's own. When a command draws a side it also
 *    draws the touching side of the cell next door, so part of what a neighbour holds is a
 *    copy of the moved cells' borders; giving that back would leave their lines behind;
 *  - each cell landing is given the sides it had of its own where it came from (the caller
 *    writes those, from `carried`), again without copies of its old neighbours' sides.
 * Which side is whose comes from a traced replay of the commands (createBorderTrace).
 */

const SIDES = ["l", "r", "t", "b"];

// Where a side's copy comes from: a command drawing the cell to the right's left side also
// draws this cell's right side, and so on.
const COPIED_FROM = { l: [0, -1], r: [0, 1], t: [-1, 0], b: [1, 0] };

// The toolbar command that draws one side of a cell, and nothing else.
const SIDE_COMMAND = { l: "border-left", r: "border-right", t: "border-top", b: "border-bottom" };

function within(r, c, { row, column }) {
    return r >= row[0] && r <= row[1] && c >= column[0] && c <= column[1];
}

/**
 * A trace for getBorderInfoComputeTraced (border.js): replays the sheet's border commands as
 * the editor does and keeps, beside what is drawn, two tallies of what is whose.
 *  - `own`: every side as it would be had no cell in `areas` ever drawn into a neighbour — what
 *    the cells around the areas hold in their own right.
 *  - `carried`: every side as it would be had no cell outside `source` ever drawn into one —
 *    what the cells being moved take with them.
 * Clearing a side counts whoever does it: a "none" that cleared a neighbour's facing side took
 * that line away for good.
 *
 * @param {Array} areas   [{ row: [r1, r2], column: [c1, c2] }, ...] the cells moved from and to
 * @param {Object|null} source  the area moved from, when this sheet is the one moved from
 */
export function createBorderTrace(areas, source) {
    const own = {};
    const carried = {};
    const drawn = {};
    let covers = () => false;

    const inAreas = (r, c) => areas.some(area => within(r, c, area));
    const inSource = (r, c) => source != null && within(r, c, source);

    const write = (tally, key, side, value) => {
        if (value == null) {
            if (tally[key]) {
                delete tally[key][side];

                if (!SIDES.some(other => tally[key][other] != null)) {
                    delete tally[key];
                }
            }
            return;
        }

        if (tally[key] == null) {
            tally[key] = {};
        }
        tally[key][side] = value;
    };

    const record = (key, side, value) => {
        const [r, c] = key.split("_").map(Number);
        const direct = covers(r, c);
        const from = [r + COPIED_FROM[side][0], c + COPIED_FROM[side][1]];

        if (direct || !inAreas(from[0], from[1])) {
            write(own, key, side, value);
        }

        if (direct || inSource(from[0], from[1])) {
            write(carried, key, side, value);
        }
    };

    const wrapEntry = (key, entry) => {
        SIDES.forEach(side => {
            if (entry[side] != null) {
                record(key, side, entry[side]);
            }
        });

        return new Proxy(entry, {
            set(target, side, value) {
                target[side] = value;
                if (SIDES.includes(side)) {
                    record(key, side, value);
                }
                return true;
            },
            deleteProperty(target, side) {
                delete target[side];
                if (SIDES.includes(side)) {
                    write(own, key, side, null);
                    write(carried, key, side, null);
                }
                return true;
            },
        });
    };

    return {
        own,
        carried,
        drawn,
        wrap(compute) {
            return new Proxy(compute, {
                set(target, key, entry) {
                    target[key] = entry != null && typeof entry === "object" ? wrapEntry(key, entry) : entry;
                    drawn[key] = target[key];
                    return true;
                },
                deleteProperty(target, key) {
                    delete target[key];
                    delete drawn[key];
                    delete own[key];
                    delete carried[key];
                    return true;
                },
            });
        },
        command(entry) {
            if (entry.rangeType === "range") {
                const ranges = entry.range || [];
                covers = (r, c) => ranges.some(range => within(r, c, range));
            } else {
                const value = entry.value || {};
                covers = (r, c) => r === value.row_index && c === value.col_index;
            }
        },
    };
}

/**
 * The border commands to save once cells have moved: `borderInfo` as it was, then the areas
 * cleared and the cells around them given back their own facing sides. The caller then gives
 * each landed cell its sides from `trace.carried`.
 *
 * @param {Array|null} borderInfo  the sheet's config.borderInfo, before the move
 * @param {Object} trace           createBorderTrace(areas, …), replayed over this sheet before the move
 * @param {Array} areas            [{ row: [r1, r2], column: [c1, c2] }, ...] the cells moved from and to
 * @param {number} rowCount        rows in the sheet
 * @param {number} columnCount     columns in the sheet
 * @returns {Array|null} the borderInfo to save; unchanged when nothing in the areas has a border
 */
export function borderInfoAfterMove(borderInfo, trace, areas, rowCount, columnCount) {
    if (!Array.isArray(borderInfo) || borderInfo.length === 0) {
        return borderInfo;
    }

    const inAnArea = (r, c) => areas.some(area => within(r, c, area));

    // Nothing drawn in either area, hidden rows included: nothing to clear, and nothing around
    // them to give back.
    const bordered = Object.keys(trace.drawn).some(key => {
        const sides = trace.drawn[key];
        const [r, c] = key.split("_").map(Number);

        return inAnArea(r, c) && sides != null && SIDES.some(side => sides[side] != null);
    });

    if (!bordered) {
        return borderInfo;
    }

    // A cell's own entries in either area say nothing any more: the "none" below clears them.
    const next = borderInfo.filter(entry => entry.rangeType !== "cell" || !inAnArea(entry.value.row_index, entry.value.col_index));

    next.push({
        rangeType: "range",
        borderType: "border-none",
        color: "#000000",
        style: "1",
        range: areas.map(({ row, column }) => ({ row: [row[0], row[1]], column: [column[0], column[1]] })),
    });

    // Each side facing an area, once: the side the "none" cleared. Only that side is written
    // back, as a one-cell command for that side alone, so nothing else about the cell changes;
    // and its other neighbour across that side is in an area and was just cleared, so nothing
    // is drawn into it either.
    const given = new Set();
    const giveBack = (r, c, side) => {
        const key = r + "_" + c;

        if (r < 0 || c < 0 || r >= rowCount || c >= columnCount || inAnArea(r, c) || given.has(key + side)) {
            return;
        }

        given.add(key + side);

        const value = trace.own[key] && trace.own[key][side];

        if (value == null) {
            return;
        }

        next.push({
            rangeType: "range",
            borderType: SIDE_COMMAND[side],
            color: value.color,
            style: value.style,
            range: [{ row: [r, r], column: [c, c] }],
        });
    };

    for (const { row, column } of areas) {
        for (let c = column[0]; c <= column[1]; c++) {
            giveBack(row[0] - 1, c, "b");
            giveBack(row[1] + 1, c, "t");
        }

        for (let r = row[0]; r <= row[1]; r++) {
            giveBack(r, column[0] - 1, "r");
            giveBack(r, column[1] + 1, "l");
        }
    }

    return next;
}
