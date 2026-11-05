// useVirtualRows windows a long list of variable-height rows inside a scroll
// container, so only the rows near the viewport are in the DOM. Built for
// table bodies (the bucket log table): the caller renders items[start, end)
// between two spacer rows of padTop / padBottom pixels.
//
//   - Rows are measured after every render (rendered rows carry data-id =
//     their key) and the heights are remembered per key, so wrapped messages
//     and rows that arrive above keep the offsets right. Rows never rendered
//     count at the running average height.
//   - Scroll anchoring: while the view is scrolled away from the top, the
//     first visible row stays put when rows are inserted above it or rows
//     above it are re-measured, so a live tail doesn't shove the page
//     around under the reader. At the very top new rows simply appear.
//   - scrollToIndex makes a row fully visible (below a sticky header, which
//     is taken to be everything above the rows' container).
//
// No dependency: the list sizes here (a few thousand rows) only need prefix
// sums and a binary search.
import { useCallback, useLayoutEffect, useMemo, useRef, useState, type RefObject } from "react";

export interface VirtualRowsOptions {
  scrollRef: RefObject<HTMLElement | null>; // the scrolling element
  bodyRef: RefObject<HTMLElement | null>; // direct parent of the rows (tbody)
  keys: readonly number[]; // one stable key per item, in display order
  estimate?: number; // row height before anything is measured
  overscan?: number; // extra rows rendered above and below the viewport
  // Changing this scrolls back to the top without anchoring (a re-sort:
  // keeping the old first row in view would be surprising).
  resetKey?: unknown;
}

export interface VirtualRows {
  start: number; // render items[start, end)
  end: number;
  padTop: number;
  padBottom: number;
  atTop: boolean; // scrolled to (within a couple of pixels of) the top
  scrollToIndex: (i: number) => void;
  scrollToTop: () => void;
}

const TOP_SLACK = 2;

interface Layout {
  keys: readonly number[];
  offs: Float64Array; // offs[i] = top of item i; offs[n] = total height
  index: Map<number, number>; // key → index
}

export function useVirtualRows({
  scrollRef,
  bodyRef,
  keys,
  estimate = 28,
  overscan = 12,
  resetKey,
}: VirtualRowsOptions): VirtualRows {
  const heights = useRef(new Map<number, number>()).current;
  const [measured, setMeasured] = useState(0); // bumps when a height changes
  const [view, setView] = useState({ top: 0, height: 0 });
  const bodyTop = useRef(0); // the rows' container offset inside the scroller
  const anchor = useRef<{ key: number; delta: number } | null>(null);

  const layout = useMemo<Layout>(() => {
    const n = keys.length;
    if (heights.size > n * 2 + 500) {
      // Forget rows long gone (trimmed, filtered away).
      const live = new Set(keys);
      for (const k of heights.keys()) if (!live.has(k)) heights.delete(k);
    }
    let sum = 0;
    let count = 0;
    for (const h of heights.values()) {
      sum += h;
      count++;
    }
    const avg = count > 0 ? sum / count : estimate;
    const offs = new Float64Array(n + 1);
    const index = new Map<number, number>();
    for (let i = 0; i < n; i++) {
      index.set(keys[i], i);
      offs[i + 1] = offs[i] + (heights.get(keys[i]) ?? avg);
    }
    return { keys, offs, index };
    // measured is the cache-busting signal for heights (a mutable map).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keys, measured, estimate]);
  const layoutRef = useRef(layout);
  layoutRef.current = layout;

  // The first row at or below y (list coordinates), and how far below y its
  // top edge is (≤ 0).
  const anchorAt = useCallback((scrollTop: number) => {
    const l = layoutRef.current;
    const n = l.keys.length;
    if (n === 0) return null;
    const y = scrollTop - bodyTop.current;
    const i = Math.min(firstEndingAfter(l.offs, y), n - 1);
    return { key: l.keys[i], delta: l.offs[i] - y };
  }, []);

  // Where the last anchor correction left scrollTop. The scroll event it
  // causes must not re-derive the anchor from the rounded position, or the
  // sub-pixel rounding of every correction would add up into a drift.
  const corrected = useRef<number | null>(null);

  const sync = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (corrected.current === null || Math.abs(el.scrollTop - corrected.current) > 1) {
      corrected.current = null;
      anchor.current = anchorAt(el.scrollTop);
    }
    setView((v) => (v.top === el.scrollTop && v.height === el.clientHeight ? v : { top: el.scrollTop, height: el.clientHeight }));
  }, [scrollRef, anchorAt]);

  // Track scrolling and the viewport size; a width change re-wraps
  // messages, so it re-measures too.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.addEventListener("scroll", sync, { passive: true });
    let width = el.clientWidth;
    const ro = new ResizeObserver(() => {
      if (el.clientWidth !== width) {
        width = el.clientWidth;
        setMeasured((m) => m + 1);
      }
      sync();
    });
    ro.observe(el);
    sync();
    return () => {
      el.removeEventListener("scroll", sync);
      ro.disconnect();
    };
  }, [scrollRef, sync]);

  // Measure what was rendered.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    const body = bodyRef.current;
    if (!el || !body) return;
    bodyTop.current = body.getBoundingClientRect().top - el.getBoundingClientRect().top + el.scrollTop;
    let changed = false;
    for (const row of body.querySelectorAll<HTMLElement>(":scope > [data-id]")) {
      const k = Number(row.dataset.id);
      const h = row.getBoundingClientRect().height;
      const old = heights.get(k);
      if (old === undefined || Math.abs(old - h) > 0.5) {
        heights.set(k, h);
        changed = true;
      }
    }
    if (changed) setMeasured((m) => m + 1);
  });

  // Keep the anchor row in place when the layout above it changes.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const a = anchor.current;
    const i = a && el.scrollTop > TOP_SLACK ? layout.index.get(a.key) : undefined;
    if (a && i !== undefined) {
      const want = Math.max(0, bodyTop.current + layout.offs[i] - a.delta);
      if (Math.abs(want - el.scrollTop) > 0.5) {
        el.scrollTop = want;
        corrected.current = el.scrollTop;
      }
    } else {
      corrected.current = null;
    }
    sync();
  }, [layout, scrollRef, sync]);

  // A new order starts at the top.
  const lastReset = useRef(resetKey);
  useLayoutEffect(() => {
    if (Object.is(lastReset.current, resetKey)) return;
    lastReset.current = resetKey;
    const el = scrollRef.current;
    if (!el) return;
    anchor.current = null;
    corrected.current = null;
    el.scrollTop = 0;
    sync();
  }, [resetKey, scrollRef, sync]);

  const scrollToIndex = useCallback(
    (i: number) => {
      const el = scrollRef.current;
      const { offs } = layoutRef.current;
      if (!el || i < 0 || i >= offs.length - 1) return;
      const head = bodyTop.current; // a sticky header covers this much
      const top = head + offs[i];
      const bottom = head + offs[i + 1];
      if (top < el.scrollTop + head) el.scrollTop = top - head;
      else if (bottom > el.scrollTop + el.clientHeight) el.scrollTop = bottom - el.clientHeight;
      sync();
    },
    [scrollRef, sync],
  );

  const scrollToTop = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = 0;
    sync();
  }, [scrollRef, sync]);

  const { offs } = layout;
  const n = keys.length;
  const y0 = view.top - bodyTop.current;
  const y1 = y0 + (view.height || 1000);
  const first = Math.min(firstEndingAfter(offs, y0), n);
  const last = Math.min(firstStartingAtOrAfter(offs, y1), n);
  const start = Math.max(0, first - overscan);
  const end = Math.min(n, last + overscan);
  return {
    start,
    end,
    padTop: offs[start],
    padBottom: offs[n] - offs[end],
    atTop: view.top <= TOP_SLACK,
    scrollToIndex,
    scrollToTop,
  };
}

// The first i with offs[i + 1] > y: the item whose box contains y (or the
// first item when y is above the list).
function firstEndingAfter(offs: Float64Array, y: number): number {
  let lo = 0;
  let hi = offs.length - 1; // number of items
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (offs[mid + 1] > y) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

// The first i with offs[i] >= y (n when y is past the end).
function firstStartingAtOrAfter(offs: Float64Array, y: number): number {
  let lo = 0;
  let hi = offs.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (offs[mid] >= y) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}
