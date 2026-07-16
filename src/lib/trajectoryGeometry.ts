// Deterministic display-mapping helpers shared by the trajectory visuals
// (plan view and vertical profile). Display concerns only: no engineering
// calculation lives here — horizontal displacement and all minimum-curvature
// values are backend-owned and guarded in Python. No DOM, randomness,
// timestamps, or viewport-dependent behaviour.

// Visual epsilon tied to the serialized display precision (coordinates are
// rounded to 0.01 ft): below this total extent there is nothing displayable —
// an honesty rule, not an engineering judgement.
export const DISPLAY_EPSILON_FT = 0.01;

export function niceTickStep(span: number): number {
  const rough = Math.max(span, DISPLAY_EPSILON_FT) / 4;
  const magnitude = Math.pow(10, Math.floor(Math.log10(rough)));
  const residual = rough / magnitude;
  const factor = residual >= 5 ? 5 : residual >= 2 ? 2 : 1;
  return factor * magnitude;
}

export function tickValues(min: number, max: number, step: number): number[] {
  const ticks: number[] = [];
  const start = Math.ceil(min / step) * step;
  for (let value = start; value <= max + step / 1000; value += step) {
    ticks.push(Number(value.toFixed(4)));
  }
  return ticks;
}

export function formatFt(value: number): string {
  return value.toLocaleString(undefined, { maximumFractionDigits: 1 });
}
