// Figura isométrica do GARIMPO (skill /anatomy).
// A máquina: uma bancada de ensaio de amostras. Um carro leva a AMOSTRA-SEED
// por um trilho e para sob quatro ESTAÇÕES-FONTE (RDAP, DNS, crt.sh,
// InternetDB). Cada estação desce um êmbolo sobre a amostra: isso é UMA
// requisição. Cada requisição enche um FRASCO no rack de custódia, e cada
// frasco é ligado ao anterior por um elo (o hash_anterior do ledger).
// O mostrador conta as requisições contra o ORÇAMENTO (8): ao entrar na zona
// vermelha a bancada para. A primeira volta é a profundidade 0; a segunda,
// com a amostra pivotada, é a profundidade 1.
//
//   node manual/figura/build.mjs            → garimpo-figura.html
//   node manual/figura/build.mjs --light    → garimpo-figura-light.html
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SKILL = process.env.ANATOMY_DIR || "/mnt/skills/plugins/anatomy";
const k = await import(`${SKILL}/kit/iso-kit.mjs`);
const { kitScript } = await import(`${SKILL}/scripts/inline-kit.mjs`);

const HERE = dirname(fileURLToPath(import.meta.url));
const theme = process.argv.includes("--light") ? "light" : "dark";

const WIDTH = 640;
const HEIGHT = 420;

// ---------------------------------------------------------------- mundo
const PLATE = { x: -168, y: -76, w: 330, d: 156, r: 9 };
const PLATE_H = 12;
const FOOT_H = 5;

const RAIL_FROM = -150;
const RAIL_TO = 112;
const RAILS_Y = [-15, 10];

const CARRIAGE = { x: -24, y: -19, w: 48, d: 36, r: 3 };
const CAR_Z = 3;
const CAR_TOP = 9;
const SEED = { x: -9, y: -9, w: 18, d: 18, r: 2 };
const SEED_TOP = CAR_TOP + 12;
const HOME = -122;

const STATIONS = [-92, -38, 16, 70];
const NAMES = ["RDAP", "DNS", "crt.sh", "InternetDB"];
const POST_Y = -50;
const POST_TOP = 82;
const ARM_Z = 74;
const ARM_TOP = 79;
const NOSE_Z = 66;
const GAP = 13; // folga entre a ponta do êmbolo e a amostra, em repouso
const TIP_REST = SEED_TOP + GAP;
const STUB_TOP = ARM_TOP + 8; // topo do êmbolo acima do braço, em repouso

const BUDGET = 8;
const DIAL = [128, -46];
const DIAL_R = 17;
const DIAL_Z = 52;
const DIAL_H = 8;
const DIAL_TOP = DIAL_Z + DIAL_H;
const SWEEP = (Math.PI * 3) / 2; // 270°
const SWEEP_FROM = -SWEEP / 2;

const TRAY = { x: -138, y: 44, w: 230, d: 22, r: 3 };
const TRAY_H = 4;
const VIAL_R = 6;
const VIAL_Y = TRAY.y + TRAY.d / 2;
const VIAL_X = Array.from({ length: BUDGET }, (_, i) => TRAY.x + 16 + i * 28.2);
const VIAL_Z = TRAY_H;
const VIAL_TOP = VIAL_Z + 15;
const CAP_TOP = VIAL_TOP + 3;

const P = k.fitProjection(
  [
    ...k.boxCorners(PLATE, -PLATE_H - FOOT_H, 0),
    [STATIONS[0], POST_Y, POST_TOP + 10],
    [STATIONS[3], POST_Y, POST_TOP + 10],
    [DIAL[0] + DIAL_R, DIAL[1], DIAL_TOP + 2],
  ],
  WIDTH,
  HEIGHT,
  { pad: 26, azimuth: 40 },
);

const at = (point) => k.iso(point, P);
const S = (paths, style) => k.solidSvg(paths, style);
const L = (d, style) => k.lineSvg(d, style);
const D = (points, style) => k.dotsSvg(points, style);
const near = (x, y) => k.depthOf([x, y, 0], P);
const byDepth = (points) => [...points].sort((a, b) => near(a[0], a[1]) - near(b[0], b[1]));

// ---------------------------------------------------------------- base
function plate() {
  const out = [`<path class="iso-halo" d="${k.haloOf(PLATE, -PLATE_H - FOOT_H, PLATE_H, P)}"/>`];
  for (const [x, y] of byDepth(k.corners(PLATE, 24))) {
    out.push(S(k.cylinder(x, y, 7.4, -PLATE_H - FOOT_H, 1.6, P, 28), { tone: "lo" }));
    out.push(S(k.cylinder(x, y, 5.6, -PLATE_H - FOOT_H + 1.6, FOOT_H - 1.6, P, 28), { tone: "mid" }));
  }
  out.push(S(k.slabOf(PLATE, -PLATE_H, PLATE_H, P, 9, 1.6), { tone: "mid", inner: L(k.sideSeam(PLATE, -PLATE_H / 2, P, 9), { tone: "faint" }) }));
  out.push(L(k.planOutline(k.insetPlan(PLATE, 5), 0, P, 9), { tone: "lo" }));
  const screws = k.corners(PLATE, 11);
  out.push(L(screws.map(([x, y]) => k.ring(x, y, 2.3, 0, P, 16)).join(""), { tone: "lo" }));
  out.push(D(screws.map(([x, y]) => at([x, y, 0])), { size: 0.5 }));

  // régua do trilho: as posições do BFS
  const strip = { x: RAIL_FROM, y: 20, w: RAIL_TO - RAIL_FROM, d: 7, r: 1 };
  out.push(S(k.slabOf(strip, 0, 0.6, P, 3), { tone: "lo", crease: "none" }));
  const ticks = k.topTicks(strip.x + 3, strip.x + strip.w - 3, 4, 5, strip.y + 0.6, 0.6, [2, 3.8], P);
  out.push(L(ticks.minor, { tone: "lo" }), L(ticks.major, { tone: "mid" }));
  // marcas das estações e da casa sobre a régua
  for (const x of STATIONS) out.push(L(k.lineOnTop([x, strip.y], [x, strip.y + strip.d], 0.6, P), { tone: "hi" }));
  out.push(D([at([HOME, strip.y + 5.2, 0.6])], { size: 0.7, tone: "hi" }));
  out.push(D([at([strip.x + 1.6, strip.y + 3.5, 0.6]), at([strip.x + strip.w - 1.6, strip.y + 3.5, 0.6])], { size: 0.4 }));

  // plaqueta com o nome gravado (o único texto do desenho) e três linhas
  const tag = { x: 100, y: 34, w: 44, d: 30, r: 2 };
  out.push(S(k.slabOf(tag, 0, 1.2, P, 3, 0.4), { tone: "lo", crease: "faint" }));
  out.push(k.faceTextSvg(k.topMatrix([tag.x + tag.w / 2, tag.y + 9], 1.2, P, "x"), "GARIMPO", { size: 4.4, tone: "mid", anchor: "middle" }));
  for (const [i, y] of [16, 20.5, 25].entries()) {
    const w = [30, 24, 28][i];
    out.push(L(k.lineOnTop([tag.x + 7, tag.y + y], [tag.x + 7 + w, tag.y + y], 1.2, P), { tone: "faint", free: true }));
  }
  out.push(D([[tag.x + 3, tag.y + 3], [tag.x + tag.w - 3, tag.y + 3], [tag.x + 3, tag.y + tag.d - 3], [tag.x + tag.w - 3, tag.y + tag.d - 3]].map(([x, y]) => at([x, y, 1.2])), { size: 0.45 }));
  return out.join("");
}

// ---------------------------------------------------------------- estações-fonte (parte fixa)
function station(x, index) {
  const out = [];
  out.push(`<path class="iso-halo" d="${k.haloOf({ x: x - 10, y: POST_Y - 10, w: 20, d: 20, r: 6 }, 0, 0.1, P)}" style="filter:blur(3px)"/>`);
  // flange de base com quatro parafusos
  const foot = { x: x - 10, y: POST_Y - 10, w: 20, d: 20, r: 3 };
  out.push(S(k.slabOf(foot, 0, 3, P, 3, 0.5), { tone: "mid" }));
  out.push(D(k.corners(foot, 3.4).map(([px, py]) => at([px, py, 3])), { size: 0.45 }));
  // coluna
  out.push(S(k.cylinder(x, POST_Y, 4, 3, POST_TOP - 3, P, 28), { tone: "mid", crease: "none", inner: L([24, 48].map((z) => k.sideArc(x, POST_Y, 4, z, P, 16)).join(""), { tone: "faint" }) }));
  // cabeçote no topo, com um ponto por estação (1..4) — a "identidade" da fonte
  const head = { x: x - 7, y: POST_Y - 7, w: 14, d: 14, r: 2.5 };
  out.push(S(k.slabOf(head, ARM_Z - 2, POST_TOP - ARM_Z + 4, P, 4, 0.6), { tone: "mid", inner: L(k.sideSeam(head, ARM_TOP, P, 4), { tone: "faint" }) }));
  const pips = Array.from({ length: index + 1 }, (_, i) => at([x - 4.5 + i * 3, POST_Y + 3.5, POST_TOP + 2]));
  out.push(D(pips, { size: 0.65, tone: "hi" }));
  // braço até o trilho
  const arm = { x: x - 3.2, y: POST_Y + 7, w: 6.4, d: -POST_Y - 7 + 4, r: 1.6 };
  out.push(S(k.slabOf(arm, ARM_Z, ARM_TOP - ARM_Z, P, 3, 0.5), { tone: "mid" }));
  out.push(D([at([x, POST_Y + 12, ARM_TOP]), at([x, -10, ARM_TOP])], { size: 0.42 }));
  // bucha-guia do êmbolo na ponta do braço
  out.push(S(k.cylinder(x, 0, 5.2, NOSE_Z, ARM_TOP - NOSE_Z, P, 32, 0.5), { tone: "mid", inner: L(k.sideArc(x, 0, 5.2, ARM_Z, P, 20), { tone: "faint" }) }));
  out.push(L(k.ring(x, 0, 2.2, ARM_TOP, P, 20), { tone: "lo" }));
  return out.join("");
}

// ---------------------------------------------------------------- êmbolos (reconstruídos ao vivo)
const rodLower = (x, tip) => S(k.cylinder(x, 0, 1.5, tip + 2.2, NOSE_Z - tip - 2.2, P, 16), { tone: "hi", crease: "none" }) + S(k.cylinder(x, 0, 3, tip, 2.2, P, 24, 0.4), { tone: "hi", lit: true });
const rodUpper = (x, tip) => {
  const top = STUB_TOP - (TIP_REST - tip);
  return S(k.cylinder(x, 0, 1.5, ARM_TOP, Math.max(0.6, top - ARM_TOP), P, 16), { tone: "hi", crease: "none" }) + S(k.cylinder(x, 0, 2.4, top, 1.6, P, 20), { tone: "mid" });
};

// ---------------------------------------------------------------- trilhos e carro
function rails() {
  const out = [];
  for (const y of RAILS_Y) {
    out.push(S(k.slabOf({ x: RAIL_FROM, y, w: RAIL_TO - RAIL_FROM, d: 5, r: 1 }, 0, 3, P, 3, 0.4), { tone: "mid" }));
    out.push(D([RAIL_FROM + 6, (RAIL_FROM + RAIL_TO) / 2, RAIL_TO - 6].map((x) => at([x, y + 2.5, 3])), { size: 0.4 }));
  }
  for (const x of [RAIL_FROM - 6, RAIL_TO]) {
    out.push(S(k.slabOf({ x, y: RAILS_Y[0] - 4, w: 6, d: RAILS_Y[1] - RAILS_Y[0] + 13, r: 1.4 }, 0, 8, P, 3, 0.5), { tone: "mid" }));
    out.push(D([at([x + 3, RAILS_Y[0], 8]), at([x + 3, RAILS_Y[1] + 5, 8])], { size: 0.45 }));
  }
  return out.join("");
}

function carriage() {
  const out = [`<path class="iso-halo" d="${k.haloOf(k.insetPlan(CARRIAGE, 3), CAR_Z, 0.1, P)}" style="filter:blur(4px)"/>`];
  // quatro buchas sobre os trilhos
  for (const [bx, by] of byDepth([[-18, RAILS_Y[0]], [12, RAILS_Y[0]], [-18, RAILS_Y[1]], [12, RAILS_Y[1]]])) {
    out.push(S(k.slabOf({ x: bx, y: by - 1, w: 7, d: 7, r: 1.2 }, 3, CAR_Z - 3 + 0.01, P, 2), { tone: "lo", crease: "none" }));
  }
  out.push(S(k.slabOf(CARRIAGE, CAR_Z, CAR_TOP - CAR_Z, P, 5, 0.6), { tone: "mid", inner: L(k.sideSeam(CARRIAGE, CAR_Z + 2.4, P, 5), { tone: "faint" }) }));
  out.push(L(k.planOutline(k.insetPlan(CARRIAGE, 3), CAR_TOP, P, 5), { tone: "faint" }));
  out.push(D([-19, 19].flatMap((x) => [[x, -14], [x, 12]]).map(([x, y]) => at([x, y, CAR_TOP])), { size: 0.42, tone: "lo" }));
  // berço da amostra
  const cradle = k.insetPlan(SEED, -2.4);
  out.push(S(k.slabOf(cradle, CAR_TOP, 2, P, 3, 0.4), { tone: "mid" }));
  // a amostra-seed: o acento aceso
  out.push(S(k.slabOf(SEED, CAR_TOP + 2, SEED_TOP - CAR_TOP - 2, P, 3, 0.6), { tone: "hi", lit: true, crease: "lo" }));
  out.push(L(k.planOutline(k.insetPlan(SEED, 3), SEED_TOP, P, 3), { tone: "faint" }));
  // manopla frontal recartilhada
  const hx = CARRIAGE.x + CARRIAGE.w - 9;
  const hy = CARRIAGE.y + CARRIAGE.d + 3;
  out.push(S(k.slabOf({ x: hx - 2, y: CARRIAGE.y + CARRIAGE.d - 1, w: 4, d: 4, r: 1 }, CAR_Z + 1, 3, P, 2), { tone: "mid", crease: "none" }));
  out.push(S(k.cylinder(hx, hy + 1, 3, CAR_Z, 5, P, 20), { tone: "mid" }));
  out.push(L(k.knurl(hx, hy + 1, 3, CAR_Z, CAR_Z + 5, 18, P), { tone: "lo" }));
  return out.join("");
}

// ---------------------------------------------------------------- mostrador do orçamento
const angleOf = (n) => SWEEP_FROM + (SWEEP * n) / BUDGET;
const needleAt = (n) => {
  const a = angleOf(n);
  const [x, y] = DIAL;
  return k.lineOnTop([x - Math.sin(a) * 3.6, y + Math.cos(a) * 3.6], [x + Math.sin(a) * (DIAL_R - 4), y - Math.cos(a) * (DIAL_R - 4)], DIAL_TOP + 0.2, P);
};
function dial() {
  const out = [];
  const [x, y] = DIAL;
  const base = { x: x - 9, y: y - 9, w: 18, d: 18, r: 3 };
  out.push(S(k.slabOf(base, 0, 4, P, 3, 0.5), { tone: "mid" }));
  out.push(D(k.corners(base, 3.2).map(([px, py]) => at([px, py, 4])), { size: 0.45 }));
  out.push(S(k.cylinder(x, y, 3, 4, DIAL_Z - 4, P, 24), { tone: "mid", crease: "none", inner: L(k.sideArc(x, y, 3, 22, P, 14), { tone: "faint" }) }));
  out.push(S(k.cylinder(x, y, DIAL_R, DIAL_Z, DIAL_H, P, 64, 0.8), { tone: "hi", crease: "lo", inner: L(k.sideArc(x, y, DIAL_R, DIAL_TOP - 3, P, 40), { tone: "faint" }) }));
  out.push(L(k.knurl(x, y, DIAL_R, DIAL_TOP - 3, DIAL_TOP, 80, P, 0.3), { tone: "lo" }));
  out.push(L(k.ring(x, y, DIAL_R - 2.2, DIAL_TOP, P, 64), { tone: "lo" }));
  const ticks = k.radialTicks(x, y, DIAL_R - 2.2, BUDGET * 4, 4, DIAL_TOP, [1.4, 3], P, SWEEP_FROM, SWEEP);
  out.push(L(ticks.minor, { tone: "lo" }), L(ticks.major, { tone: "mid" }));
  // tique final
  const end = angleOf(BUDGET);
  out.push(L(k.lineOnTop([x + Math.sin(end) * (DIAL_R - 2.2), y - Math.cos(end) * (DIAL_R - 2.2)], [x + Math.sin(end) * (DIAL_R - 5.2), y - Math.cos(end) * (DIAL_R - 5.2)], DIAL_TOP, P), { tone: "mid" }));
  // zona vermelha: a última requisição do orçamento
  const red = [];
  for (let i = 0; i <= 16; i++) {
    const a = angleOf(BUDGET - 1) + ((angleOf(BUDGET) - angleOf(BUDGET - 1)) * i) / 16;
    red.push([x + Math.sin(a) * (DIAL_R - 2.2), y - Math.cos(a) * (DIAL_R - 2.2)]);
  }
  out.push(`<path class="iso-line" data-tone="red" d="${k.onTop(red, DIAL_TOP, P)}" style="stroke-width:1.6"/>`);
  // coroa lateral
  out.push(S(k.slabOf({ x: x - 2.4, y: y - DIAL_R - 4, w: 4.8, d: 5, r: 1.2 }, DIAL_Z + 2, 4, P, 3), { tone: "mid" }));
  out.push(S(k.slabOf({ x: x - 3.2, y: y - DIAL_R - 6.4, w: 6.4, d: 2.6, r: 1.2 }, DIAL_Z + 1.2, 5.6, P, 3), { tone: "mid" }));
  out.push(L(k.ring(x, y, 1.6, DIAL_TOP, P, 16), { tone: "mid" }));
  return out.join("");
}

// ---------------------------------------------------------------- rack de custódia
function tray() {
  const out = [`<path class="iso-halo" d="${k.haloOf(TRAY, 0, TRAY_H, P)}"/>`];
  out.push(S(k.slabOf(TRAY, 0, TRAY_H, P, 4, 0.6), { tone: "lo", inner: L(k.sideSeam(TRAY, 1.6, P, 4), { tone: "faint" }) }));
  out.push(D([[TRAY.x + 4, TRAY.y + 4], [TRAY.x + TRAY.w - 4, TRAY.y + 4], [TRAY.x + 4, TRAY.y + TRAY.d - 4], [TRAY.x + TRAY.w - 4, TRAY.y + TRAY.d - 4]].map(([x, y]) => at([x, y, TRAY_H])), { size: 0.45 }));
  return out.join("");
}
function vial(i) {
  const x = VIAL_X[i];
  const y = VIAL_Y;
  const out = [];
  out.push(L(k.ring(x, y, VIAL_R + 1.4, TRAY_H, P, 28), { tone: "faint" }));
  out.push(S(k.cylinder(x, y, VIAL_R, VIAL_Z, VIAL_TOP - VIAL_Z, P, 32), { tone: "lo", crease: "none", inner: L(k.sideArc(x, y, VIAL_R, VIAL_Z + 3, P, 20), { tone: "faint" }) }));
  // conteúdo (evidência coletada): aparece quando a requisição acontece
  out.push(`<g data-fill="${i}" opacity="0">${S(k.cylinder(x, y, VIAL_R - 0.01, VIAL_Z + 0.6, VIAL_TOP - VIAL_Z - 4, P, 32), { tone: "hi", lit: true, crease: "none" })}</g>`);
  out.push(S(k.cylinder(x, y, VIAL_R + 0.5, VIAL_TOP, CAP_TOP - VIAL_TOP, P, 32, 0.4), { tone: "mid" }));
  out.push(L(k.knurl(x, y, VIAL_R + 0.5, VIAL_TOP, CAP_TOP, 24, P), { tone: "lo" }));
  // lacre (SHA-256): o ponto aceso no topo da tampa
  out.push(L(k.ring(x, y, 2.4, CAP_TOP, P, 20), { tone: "lo" }));
  out.push(`<g data-seal="${i}" opacity="0.18">${S(k.cylinder(x, y, 1.7, CAP_TOP, 0.7, P, 16), { tone: "hi", lit: true, crease: "none" })}</g>`);
  return out.join("");
}
// elo i: do frasco i ao i+1 (hash_anterior)
const linkPoints = (i) => [at([VIAL_X[i] + 2.4, VIAL_Y, CAP_TOP]), at([VIAL_X[i + 1] - 2.4, VIAL_Y, CAP_TOP])];
function links() {
  const out = [];
  for (let i = 0; i < BUDGET - 1; i++) {
    const [a, b] = linkPoints(i);
    out.push(`<g data-link="${i}" opacity="0.15">${k.wireSvg(a, b, { tone: "lit", size: 0.9 })}</g>`);
  }
  return out.join("");
}

// ---------------------------------------------------------------- montagem (ordem de pintura)
const stationsBack = STATIONS.map((x, i) => [x, i]).sort((a, b) => near(a[0], POST_Y) - near(b[0], POST_Y));
const startX = HOME;
const svg = k.figureSvg({
  width: WIDTH,
  height: HEIGHT,
  label:
    "Bancada de ensaio do GARIMPO. Um carro leva a amostra-seed por um trilho e para sob quatro estações-fonte (RDAP, DNS, crt.sh e InternetDB). Em cada parada o êmbolo da estação desce sobre a amostra: uma requisição. Cada requisição enche um frasco no rack de custódia, ligado ao frasco anterior por um elo. Um mostrador conta as requisições contra o orçamento de oito; na zona vermelha a bancada para.",
  body: [
    plate(),
    ...stationsBack.map(([x, i]) => station(x, i)),
    dial(),
    `<path data-part="needle" class="iso-line" data-tone="lit" data-free="start" d="${needleAt(0)}" style="stroke-width:1.1"/>`,
    rails(),
    `<g data-part="carriage" transform="${k.translateAlong(P, [startX, 0, 0])}">${carriage()}</g>`,
    ...STATIONS.map((x, i) => `<g data-rod="${i}">${rodLower(x, TIP_REST)}</g>`),
    ...stationsBack.map(([x, i]) => `<g data-stub="${i}">${rodUpper(x, TIP_REST)}</g>`),
    tray(),
    ...VIAL_X.map((_, i) => i).sort((a, b) => near(VIAL_X[a], VIAL_Y) - near(VIAL_X[b], VIAL_Y)).map(vial),
    links(),
  ],
});

// ---------------------------------------------------------------- comportamento ao vivo
const live = `
const P = ${JSON.stringify(P)};
const STATIONS = ${JSON.stringify(STATIONS)}, NAMES = ${JSON.stringify(NAMES)};
const HOME = ${HOME}, BUDGET = ${BUDGET}, TIP_REST = ${TIP_REST}, SEED_TOP = ${SEED_TOP};
const NOSE_Z = ${NOSE_Z}, ARM_TOP = ${ARM_TOP}, STUB_TOP = ${STUB_TOP};
const DIAL = ${JSON.stringify(DIAL)}, DIAL_R = ${DIAL_R}, DIAL_TOP = ${DIAL_TOP}, SWEEP = ${SWEEP}, SWEEP_FROM = ${SWEEP_FROM};
const REACH = [${RAIL_FROM + 26}, ${RAIL_TO - 26}];
const angleOf = ${angleOf.toString()};
const needleAt = ${needleAt.toString().replace("k.lineOnTop", "lineOnTop")};
const rodLower = ${rodLower.toString().replace(/k\./g, "").replace(/\bS\(/g, "solidSvg(")};
const rodUpper = ${rodUpper.toString().replace(/k\./g, "").replace(/\bS\(/g, "solidSvg(")};
const stage = document.querySelector(".iso-stage");
const svg = stage.querySelector("svg");
const carriage = svg.querySelector('[data-part="carriage"]');
const needle = svg.querySelector('[data-part="needle"]');
const rods = STATIONS.map((_, i) => svg.querySelector('[data-rod="' + i + '"]'));
const stubs = STATIONS.map((_, i) => svg.querySelector('[data-stub="' + i + '"]'));
const fills = Array.from({ length: BUDGET }, (_, i) => svg.querySelector('[data-fill="' + i + '"]'));
const seals = Array.from({ length: BUDGET }, (_, i) => svg.querySelector('[data-seal="' + i + '"]'));
const chain = Array.from({ length: BUDGET - 1 }, (_, i) => svg.querySelector('[data-link="' + i + '"]'));
const readout = document.querySelector("[data-readout]");
const still = matchMedia("(prefers-reduced-motion: reduce)");
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const ease = (cur, want, dt, s) => (still.matches ? want : cur + (want - cur) * (1 - Math.exp(-dt / s)));

let x = HOME, target = HOME, touring = true, visible = false, frame = 0, last = 0, idleTimer = 0;
let requests = 0, pressed = new Set(), dwell = 0, hold = 0, shown = 0;
const press = STATIONS.map(() => ({ at: 0, rate: 0, want: 0, counted: false }));
const glow = Array.from({ length: BUDGET }, () => 0);

const depthNow = () => (requests < STATIONS.length ? 0 : 1);
const stationAt = (cx) => STATIONS.findIndex((s) => Math.abs(s - cx) < 1.2);
function reset() {
  requests = 0; pressed = new Set(); hold = 0;
  press.forEach((p) => { p.want = 0; p.counted = false; });
}
function nextTarget() {
  if (requests >= BUDGET) return HOME;
  const i = STATIONS.findIndex((_, j) => !pressed.has(j));
  return STATIONS[i];
}
function say() {
  let text;
  if (requests >= BUDGET) text = "orçamento esgotado · 8/8";
  else {
    const i = stationAt(x);
    const where = i >= 0 ? NAMES[i] : (Math.abs(x - HOME) < 2 ? "casa" : "a caminho");
    text = where + " · prof " + depthNow() + " · " + requests + "/" + BUDGET;
  }
  if (readout.textContent !== text) readout.textContent = text;
  stage.setAttribute("aria-valuetext", text);
}
function draw() {
  carriage.setAttribute("transform", translateAlong(P, [x, 0, 0]));
  press.forEach((p, i) => {
    if (p.drawn === p.at) return;
    p.drawn = p.at;
    const tip = TIP_REST - p.at;
    rods[i].innerHTML = rodLower(STATIONS[i], tip);
    stubs[i].innerHTML = rodUpper(STATIONS[i], tip);
  });
  needle.setAttribute("d", needleAt(shown));
  glow.forEach((g, i) => {
    fills[i].setAttribute("opacity", g.toFixed(3));
    seals[i].setAttribute("opacity", (0.18 + 0.82 * g).toFixed(3));
    if (i > 0) chain[i - 1].setAttribute("opacity", (0.15 + 0.85 * Math.min(g, glow[i - 1])).toFixed(3));
  });
  say();
}
function tick(now) {
  const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60;
  last = now;
  if (touring) target = nextTarget();
  x = ease(x, target, dt, 0.32);
  if (Math.abs(target - x) < 0.02) x = target;

  // permanecer parado sob uma estação → o êmbolo desce (uma requisição)
  const i = stationAt(x);
  const parked = Math.abs(target - x) < 0.05;
  dwell = parked && i >= 0 ? dwell + dt : 0;
  if (i >= 0 && dwell > 0.35 && !pressed.has(i) && requests < BUDGET && press[i].want === 0) press[i].want = GAP_PRESS;
  press.forEach((p, j) => {
    const stiff = 380, drag = still.matches ? 2 * Math.sqrt(stiff) : 24;
    for (let n = 0; n < 4; n++) { p.rate += ((p.want - p.at) * stiff - p.rate * drag) * dt / 4; p.at += p.rate * dt / 4; }
    if (Math.abs(p.want - p.at) < 0.01 && Math.abs(p.rate) < 0.01) { p.at = p.want; p.rate = 0; }
    if (p.want > 0 && p.at > GAP_PRESS - 0.3 && !p.counted) {
      p.counted = true; requests += 1; pressed.add(j);
      if (pressed.size === STATIONS.length && requests < BUDGET) pressed = new Set(); // pivô: nova volta
      setTimeout(() => { p.want = 0; }, still.matches ? 0 : 260);
    }
    if (p.want === 0 && p.at === 0) p.counted = false;
  });
  shown = ease(shown, requests, dt, 0.25);
  if (Math.abs(shown - requests) < 0.002) shown = requests;
  glow.forEach((g, n) => { glow[n] = ease(g, n < requests ? 1 : 0, dt, 0.3); if (Math.abs(glow[n] - (n < requests ? 1 : 0)) < 0.002) glow[n] = n < requests ? 1 : 0; });

  if (touring && requests >= BUDGET && x === HOME) { hold += dt; if (hold > 2.6) reset(); }
  draw();
  const settled = !touring && x === target && press.every((p) => p.at === p.want && p.rate === 0) && shown === requests && glow.every((g, n) => g === (n < requests ? 1 : 0)) && !(i >= 0 && !pressed.has(i) && requests < BUDGET);
  frame = visible && !settled ? requestAnimationFrame(tick) : 0;
}
const GAP_PRESS = ${GAP};
const run = () => { if (!frame && visible) { last = 0; frame = requestAnimationFrame(tick); } };
const steer = (next) => {
  touring = false; target = clamp(next, REACH[0], REACH[1]);
  const snap = STATIONS.find((s) => Math.abs(s - target) < 6);
  if (snap !== undefined) target = snap;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { touring = !still.matches; if (requests >= BUDGET) reset(); run(); }, 3600);
  run();
};
new IntersectionObserver((entries) => { visible = entries[entries.length - 1].isIntersecting; if (visible) run(); }, { rootMargin: "120px 0px" }).observe(stage);
if (still.matches) { touring = false; requests = 5; shown = 5; glow.forEach((_, n) => { glow[n] = n < 5 ? 1 : 0; }); x = target = STATIONS[1]; pressed = new Set([0, 1]); }
stage.addEventListener("pointermove", (event) => {
  const box = svg.getBoundingClientRect();
  const share = clamp(((event.clientX - box.left) / box.width - 0.12) / 0.62, 0, 1);
  steer(REACH[0] + share * (REACH[1] - REACH[0]));
});
stage.addEventListener("keydown", (event) => {
  const here = STATIONS.reduce((best, s, n) => (Math.abs(s - target) < Math.abs(STATIONS[best] - target) ? n : best), 0);
  let to = null;
  if (event.key === "ArrowRight" || event.key === "ArrowUp") to = Math.min(STATIONS.length - 1, here + 1);
  if (event.key === "ArrowLeft" || event.key === "ArrowDown") to = Math.max(0, here - 1);
  if (event.key === "Home") to = 0;
  if (event.key === "End") to = STATIONS.length - 1;
  if (event.key === "Escape") { reset(); to = here; }
  if (to === null) return;
  event.preventDefault();
  steer(STATIONS[to]);
});
draw();
`;

const body = k.plateHtml({
  fig: "Fig 0",
  title: "Bancada GARIMPO",
  hint: "Mouse ou ←/→ guiam o carro",
  readout: "casa · prof 0 · 0/8",
  keys: [
    { mark: "lit", label: "Amostra-seed, êmbolo, frascos e lacres: o que muda a cada requisição" },
    { mark: "raised", label: "Quatro estações-fonte: RDAP, DNS, crt.sh, InternetDB (1 a 4 pontos no cabeçote)" },
    { mark: "red", label: "Zona vermelha: a última requisição do orçamento" },
  ],
  caption:
    "O carro só para sob estações-fonte, nunca na infraestrutura do alvo. Cada descida de êmbolo é uma requisição real: a resposta bruta vai para um frasco, e cada frasco é ligado ao anterior por um elo (o hash_anterior do ledger). Depois das quatro estações, a mesma amostra dá uma segunda volta (o pivô, profundidade 1). Na oitava requisição o ponteiro entra no vermelho e a bancada volta para casa.",
  body: `<div class="iso-stage" tabindex="0" role="slider" aria-label="Bancada GARIMPO: setas movem o carro de estação em estação; Esc zera o orçamento" aria-valuemin="0" aria-valuemax="${BUDGET}" aria-valuenow="0">${svg}</div>`,
});

const name = theme === "light" ? "garimpo-figura-light.html" : "garimpo-figura.html";
writeFileSync(join(HERE, name), k.pageHtml({ title: "Bancada GARIMPO", theme, body, script: kitScript() + live }).replace('<html lang="en">', '<html lang="pt-BR">'));
console.log("wrote", name);
