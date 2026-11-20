import * as T from "three";
import { RoundedBoxGeometry } from "three/examples/jsm/geometries/RoundedBoxGeometry.js";
import { kindNames, type NodeKind } from "./model";

type Vector = [number, number, number];
const axes: Vector = [0, 0, 0];
function physical(
  color: string,
  metalness: number,
  roughness: number,
  emissive?: string,
) {
  return new T.MeshStandardMaterial({
    color,
    metalness,
    roughness,
    ...(emissive ? { emissive, emissiveIntensity: 0.38 } : {}),
  });
}
function silhouette(points: [number, number][], depth: number) {
  const shape = new T.Shape();
  points.forEach(([x, y], i) => (i ? shape.lineTo(x, y) : shape.moveTo(x, y)));
  shape.closePath();
  const geometry = new T.ExtrudeGeometry(shape, {
    depth,
    bevelEnabled: true,
    bevelSize: 0.024,
    bevelThickness: 0.022,
    bevelSegments: 2,
    curveSegments: 3,
  });
  geometry.translate(0, 0, -depth / 2);
  return geometry;
}

/** Shared die-cast parts and machined housings; no material encodes trust state. */
export function sculptureLibrary(dark: boolean) {
  const m = {
    night: physical(dark ? "#41334d" : "#33283c", 0.72, 0.3),
    shell: physical("#795597", 0.65, 0.28),
    satin: physical("#b6a6c9", 0.79, 0.24),
    alloy: physical("#dfd0ef", 0.8, 0.21),
    core: physical("#a16bee", 0.44, 0.19, "#6229b3"),
    light: physical("#ebb4ff", 0.28, 0.17, "#bb75e4"),
    rim: physical("#b36dec", 0.64, 0.21, "#693795"),
    recess: physical("#241d30", 0.45, 0.32),
  };
  const g = {
    plate: new T.CylinderGeometry(0.7, 0.64, 0.085, 6),
    ringBase: new T.CylinderGeometry(0.63, 0.67, 0.043, 6),
    disc: new T.CylinderGeometry(0.53, 0.56, 0.055, 32),
    cube: new RoundedBoxGeometry(1, 1, 1, 2, 0.075),
    eye: new T.SphereGeometry(0.5, 24, 12),
    pyramid: new T.OctahedronGeometry(0.52, 0),
    bevelDiamond: new T.IcosahedronGeometry(0.49, 0),
    torus: new T.TorusGeometry(0.5, 0.035, 8, 40),
    thickTorus: new T.TorusGeometry(0.48, 0.062, 8, 40),
    arc: new T.TorusGeometry(0.48, 0.043, 8, 38, Math.PI * 1.62),
    smallRing: new T.TorusGeometry(0.5, 0.017, 6, 32),
    hex: new T.CylinderGeometry(0.5, 0.5, 1, 6),
    narrow: new T.CylinderGeometry(0.5, 0.5, 1, 18),
    shaft: new T.CylinderGeometry(0.3, 0.42, 1, 8),
    head: new T.IcosahedronGeometry(0.35, 1),
    action: silhouette(
      [
        [-0.47, 0.12],
        [-0.05, 0.12],
        [-0.05, 0.34],
        [0.49, 0],
        [-0.05, -0.34],
        [-0.05, -0.12],
        [-0.47, -0.12],
      ],
      0.18,
    ),
    jaw: silhouette(
      [
        [-0.11, -0.44],
        [0.09, -0.44],
        [0.11, -0.05],
        [0.31, 0.1],
        [0.32, 0.23],
        [0.24, 0.36],
        [0.12, 0.17],
        [-0.03, 0.16],
        [-0.13, 0.28],
        [-0.07, 0.42],
        [-0.22, 0.39],
        [-0.31, 0.21],
        [-0.26, 0.05],
        [-0.1, -0.07],
      ],
      0.19,
    ),
  };
  type Part = keyof typeof g;
  type Finish = keyof typeof m;
  const templates = new Map<NodeKind, T.Group>();
  function mount(
    parent: T.Group,
    part: Part,
    finish: Finish,
    p: Vector = axes,
    scale: Vector = [1, 1, 1],
    rot: Vector = axes,
  ) {
    const mesh = new T.Mesh(g[part], m[finish]);
    mesh.position.set(...p);
    mesh.scale.set(...scale);
    mesh.rotation.set(...rot);
    parent.add(mesh);
    return mesh;
  }
  function make(kind: NodeKind) {
    const unit = new T.Group();
    mount(
      unit,
      "plate",
      "night",
      [0, 0.005, 0],
      [1, 1, 1],
      [0, Math.PI / 6, 0],
    );
    mount(
      unit,
      "ringBase",
      "rim",
      [0, 0.046, 0],
      [1, 1, 1],
      [0, Math.PI / 6, 0],
    );
    mount(
      unit,
      "plate",
      "shell",
      [0, 0.09, 0],
      [0.92, 0.68, 0.92],
      [0, Math.PI / 6, 0],
    );
    mount(unit, "disc", "recess", [0, 0.125, 0]);
    mount(
      unit,
      "smallRing",
      "satin",
      [0, 0.16, 0],
      [1, 1, 1],
      [Math.PI / 2, 0, 0],
    );
    for (let i = 0; i < 3; i++) {
      const a = Math.PI / 6 + (i * Math.PI * 2) / 3;
      mount(
        unit,
        "hex",
        "alloy",
        [Math.cos(a) * 0.56, 0.135, Math.sin(a) * 0.56],
        [0.045, 0.033, 0.045],
      );
    }
    const body = new T.Group();
    body.position.y = 0.16;
    body.rotation.y = -0.32;
    unit.add(body);
    const add = (
      part: Part,
      finish: Finish,
      p: Vector,
      scale: Vector = [1, 1, 1],
      rot: Vector = axes,
    ) => mount(body, part, finish, p, scale, rot);
    switch (kind) {
      case "human":
        add("narrow", "night", [0, 0.075, 0], [0.44, 0.15, 0.44]);
        add("eye", "shell", [0, 0.23, 0], [0.88, 0.49, 0.48]);
        add("shaft", "satin", [0, 0.4, 0], [0.76, 0.31, 0.53]);
        add("head", "alloy", [0, 0.69, 0], [0.79, 1.03, 0.83], [0.02, 0.45, 0]);
        add(
          "cube",
          "recess",
          [0, 0.73, 0.23],
          [0.39, 0.095, 0.05],
          [-0.13, 0, 0],
        );
        add("cube", "light", [0, 0.745, 0.26], [0.27, 0.019, 0.018]);
        add("arc", "rim", [0, 0.53, -0.03], [1.17, 1.1, 1], [0.1, -0.39, -0.4]);
        break;
      case "agent":
        add("narrow", "satin", [0, 0.16, 0], [0.35, 0.23, 0.35]);
        add(
          "pyramid",
          "core",
          [0, 0.55, 0],
          [0.74, 0.94, 0.76],
          [0.08, 0.6, -0.06],
        );
        add(
          "thickTorus",
          "alloy",
          [0, 0.54, 0],
          [1.04, 1.04, 1],
          [1.19, 0.42, -0.62],
        );
        add("arc", "rim", [0, 0.55, 0], [1, 1, 1], [-0.52, 0.1, -0.48]);
        add("eye", "light", [0.4, 0.7, 0.13], [0.105, 0.105, 0.105]);
        break;
      case "process":
        add("cube", "satin", [0, 0.15, 0], [0.78, 0.17, 0.78]);
        add("cube", "night", [0, 0.27, 0], [0.68, 0.14, 0.66]);
        add("cube", "core", [0, 0.39, 0], [0.46, 0.18, 0.44]);
        add("cube", "alloy", [0, 0.49, 0], [0.41, 0.04, 0.4]);
        add("cube", "rim", [0, 0.52, 0], [0.21, 0.025, 0.22]);
        for (let i = -2; i <= 2; i++)
          for (const side of [-1, 1]) {
            add(
              "cube",
              "satin",
              [side * 0.415, 0.12, i * 0.105],
              [0.15, 0.056, 0.047],
            );
            add(
              "cube",
              "satin",
              [i * 0.105, 0.12, side * 0.415],
              [0.047, 0.056, 0.15],
            );
          }
        break;
      case "workload":
      case "service":
        if (kind === "workload") {
          for (let i = 0; i < 3; i++) {
            add(
              "cube",
              i === 1 ? "shell" : "night",
              [0, 0.15 + i * 0.18, 0],
              [0.82, 0.16, 0.52],
            );
            add("cube", "satin", [0, 0.19 + i * 0.18, 0], [0.78, 0.045, 0.51]);
            add(
              "cube",
              "light",
              [-0.22, 0.145 + i * 0.18, 0.273],
              [0.18, 0.018, 0.025],
            );
            add(
              "cube",
              "rim",
              [0.18, 0.145 + i * 0.18, 0.273],
              [0.21, 0.02, 0.025],
            );
          }
        } else {
          for (const [x, h, z] of [
            [-0.18, 0.63, 0.02],
            [0.17, 0.9, -0.1],
          ]) {
            add("cube", "shell", [x, h / 2, z], [0.3, h, 0.38]);
            add("cube", "alloy", [x, h + 0.01, z], [0.305, 0.05, 0.39]);
            add(
              "cube",
              "night",
              [x, h * 0.53, z + 0.19],
              [0.215, h * 0.74, 0.025],
            );
            for (let i = 0; i < 3; i++)
              add(
                "cube",
                i === 2 ? "light" : "satin",
                [x, h * 0.67 - i * 0.09, z + 0.215],
                [0.15, 0.024, 0.014],
              );
          }
        }
        break;
      case "tool":
        add("hex", "satin", [0, 0.1, 0], [0.48, 0.18, 0.48]);
        add(
          "shaft",
          "night",
          [-0.1, 0.34, 0],
          [0.7, 0.43, 0.62],
          [0, 0, -0.29],
        );
        add("jaw", "alloy", [0.06, 0.61, 0], [1, 1, 1], [0.1, 0.16, -0.5]);
        add(
          "cube",
          "core",
          [-0.04, 0.44, 0.11],
          [0.055, 0.29, 0.027],
          [0.06, 0.08, -0.48],
        );
        break;
      case "action":
        add("hex", "satin", [0, 0.07, 0], [0.47, 0.13, 0.48]);
        add("shaft", "night", [0, 0.25, 0], [0.4, 0.31, 0.38]);
        add(
          "action",
          "night",
          [-0.035, 0.58, -0.07],
          [1.08, 1.03, 1.18],
          [0, -0.24, 0.22],
        );
        add("action", "core", [0, 0.6, 0.065], [1, 1, 0.76], [0, -0.24, 0.22]);
        add(
          "cube",
          "light",
          [-0.22, 0.58, 0.17],
          [0.24, 0.027, 0.02],
          [0, -0.19, 0.22],
        );
        break;
      case "evidence":
        add("hex", "night", [0, 0.34, 0], [0.83, 0.62, 0.83], [0, 0.5, 0]);
        add("hex", "alloy", [0, 0.67, 0], [0.83, 0.07, 0.83], [0, 0.5, 0]);
        for (const h of [0.12, 0.48, 0.56])
          add("hex", "rim", [0, h, 0], [0.855, 0.035, 0.855], [0, 0.5, 0]);
        add("hex", "core", [0, 0.72, 0], [0.4, 0.05, 0.4]);
        break;
      case "unknown":
        add("arc", "satin", [0, 0.5, 0], [0.78, 0.78, 1], [0.25, -0.46, 0.52]);
        add("arc", "shell", [0, 0.52, 0], [0.61, 0.71, 1], [-0.15, 0.22, -2.7]);
        add("bevelDiamond", "core", [0, 0.5, 0], [0.32, 0.52, 0.3]);
        break;
    }
    return unit;
  }
  return {
    make(kind: NodeKind) {
      const key = Object.hasOwn(kindNames, kind) ? kind : "unknown";
      if (!templates.has(key)) templates.set(key, make(key));
      return templates.get(key)!.clone(true);
    },
    dispose() {
      Object.values(g).forEach((x) => x.dispose());
      Object.values(m).forEach((x) => x.dispose());
      templates.clear();
    },
  };
}
export function studioReflections() {
  // A local strip-light environment gives polished metal readable silhouettes
  // without external HDRI downloads or a source of telemetry.
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 128;
  const context = canvas.getContext("2d")!;
  const bg = context.createLinearGradient(0, 0, 0, 128);
  bg.addColorStop(0, "#716782");
  bg.addColorStop(0.46, "#342b43");
  bg.addColorStop(0.51, "#a39dae");
  bg.addColorStop(1, "#393142");
  context.fillStyle = bg;
  context.fillRect(0, 0, 256, 128);
  for (const [x, y, w, h, color] of [
    [10, 12, 48, 21, "#fff8ff"],
    [114, 20, 15, 50, "#e9cfff"],
    [190, 35, 42, 8, "#e8daff"],
    [25, 64, 90, 3, "#c3a7dd"],
  ] as const) {
    context.fillStyle = color;
    context.fillRect(x, y, w, h);
  }
  const texture = new T.CanvasTexture(canvas);
  texture.mapping = T.EquirectangularReflectionMapping;
  texture.colorSpace = T.SRGBColorSpace;
  return texture;
}
