"use client";

import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { Box } from "lucide-react";
import {
  kindNames,
  type GraphCommand,
  type GraphLayout,
  type PlotNode,
  type TopologyNode,
} from "./model";
import { sculptureLibrary, studioReflections } from "./TopologySculpture";

interface Props {
  layout: GraphLayout;
  mode: "light" | "command";
  selected: string;
  onSelect: (node: TopologyNode) => void;
  command: GraphCommand | null;
  onFallback: () => void;
}
type Runtime = {
  command: (c: GraphCommand) => void;
  select: (id: string) => void;
};
const up = new THREE.Vector3(0, 1, 0);
const position = (n: PlotNode) => new THREE.Vector3(n.x / 72, 0, n.y / 57);

function specimenLabel(n: PlotNode, dark: boolean) {
  const canvas = document.createElement("canvas"),
    ctx = canvas.getContext("2d")!;
  const name = n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label;
  ctx.font = "650 18px Inter,system-ui,sans-serif";
  const width = Math.ceil(Math.max(98, ctx.measureText(name).width + 24)),
    height = 49,
    scale = 2;
  canvas.width = width * scale;
  canvas.height = height * scale;
  ctx.scale(scale, scale);
  ctx.fillStyle = dark ? "#271e30" : "#fcfaff";
  ctx.strokeStyle = dark ? "#735884" : "#baabca";
  ctx.lineWidth = 1.2;
  ctx.beginPath();
  ctx.roundRect(1, 1, width - 2, height - 2, 6);
  ctx.fill();
  ctx.stroke();
  ctx.fillStyle = dark ? "#d5aae9" : "#765387";
  ctx.font = "600 10px ui-monospace,monospace";
  ctx.fillText((kindNames[n.kind] ?? "Identity").toUpperCase(), 10, 16);
  ctx.fillStyle = dark ? "#faf1ff" : "#292134";
  ctx.font = "650 18px Inter,system-ui,sans-serif";
  ctx.fillText(name, 10, 37);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  const material = new THREE.SpriteMaterial({
    map: texture,
    transparent: true,
    depthTest: false,
    depthWrite: false,
    toneMapped: false,
  });
  const sprite = new THREE.Sprite(material);
  sprite.scale.set(width * 0.0106, height * 0.0106, 1);
  sprite.position.copy(position(n)).add(new THREE.Vector3(0, 1.47, 0.0));
  sprite.renderOrder = 5;
  sprite.userData.nodeId = n.id;
  return { sprite, texture };
}
function contactPatch() {
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = 96;
  const c = canvas.getContext("2d")!,
    gr = c.createRadialGradient(48, 48, 8, 48, 48, 47);
  gr.addColorStop(0, "rgba(42,18,48,.72)");
  gr.addColorStop(0.49, "rgba(52,30,64,.38)");
  gr.addColorStop(1, "rgba(65,44,84,0)");
  c.fillStyle = gr;
  c.fillRect(0, 0, 96, 96);
  return new THREE.CanvasTexture(canvas);
}

export default function Topology3D({
  layout,
  mode,
  onSelect,
  selected,
  command,
  onFallback,
}: Props) {
  const target = useRef<HTMLDivElement>(null),
    runtime = useRef<Runtime | null>(null),
    selectRef = useRef(onSelect),
    selection = useRef(selected);
  selectRef.current = onSelect;
  selection.current = selected;
  const [failure, setFailure] = useState(false);
  useEffect(() => {
    const host = target.current;
    if (!host) return;
    const dark = mode === "command";
    setFailure(false);
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        alpha: true,
        antialias: true,
        powerPreference: "low-power",
      });
    } catch {
      setFailure(true);
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = dark ? 1.1 : 0.99;
    renderer.domElement.setAttribute("aria-hidden", "true");
    host.appendChild(renderer.domElement);
    const scene = new THREE.Scene(),
      camera = new THREE.PerspectiveCamera(40, 1, 0.04, 5000);
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = false;
    controls.minDistance = 1.8;
    controls.maxDistance = 3000;
    controls.maxPolarAngle = Math.PI * 0.48;
    const environment = studioReflections();
    scene.environment = environment;
    scene.environmentIntensity = dark ? 0.77 : 0.83;
    scene.add(
      new THREE.HemisphereLight(0xf1defc, dark ? 0x352140 : 0x8d7994, 1.8),
    );
    const key = new THREE.DirectionalLight(0xfff1ff, 3.1);
    key.position.set(-4, 8, 5);
    scene.add(key);
    const rim = new THREE.DirectionalLight(0xb588ff, 2.6);
    rim.position.set(5, 3, -6);
    scene.add(rim);
    const kit = sculptureLibrary(dark),
      plot = new Map<string, THREE.Group>(),
      labels: THREE.Sprite[] = [],
      labelTextures: THREE.Texture[] = [];
    const nodeRecords = new Map(layout.nodes.map((n) => [n.id, n]));
    const contact = contactPatch(),
      contactGeo = new THREE.PlaneGeometry(1.99, 1.75),
      contactMat = new THREE.MeshBasicMaterial({
        map: contact,
        transparent: true,
        depthWrite: false,
        toneMapped: false,
      });
    const clickable: THREE.Object3D[] = [];
    for (const n of layout.nodes) {
      const object = kit.make(n.kind);
      object.position.copy(position(n));
      object.traverse((child) => {
        child.userData.nodeId = n.id;
      });
      plot.set(n.id, object);
      scene.add(object);
      clickable.push(object);
      const shadow = new THREE.Mesh(contactGeo, contactMat);
      shadow.rotation.x = -Math.PI / 2;
      shadow.position.copy(object.position);
      shadow.position.y = -0.048;
      scene.add(shadow);
      const tag = specimenLabel(n, dark);
      scene.add(tag.sprite);
      labels.push(tag.sprite);
      labelTextures.push(tag.texture);
      clickable.push(tag.sprite);
    }
    const bounds = new THREE.Box3().setFromPoints(
        [...plot.values()].map((o) => o.position),
      ),
      center = bounds.getCenter(new THREE.Vector3()),
      span = bounds.getSize(new THREE.Vector3());
    const boardW = Math.max(span.x + 3.5, 5),
      boardD = Math.max(span.z + 3.0, 4);
    const substrateGeo = new THREE.PlaneGeometry(boardW, boardD);
    const substrateMaterial = new THREE.MeshStandardMaterial({
      color: dark ? "#272032" : "#e4dce9",
      metalness: 0.1,
      roughness: 0.88,
    });
    const board = new THREE.Mesh(substrateGeo, substrateMaterial);
    board.rotation.x = -Math.PI / 2;
    board.position.set(center.x, -0.082, center.z);
    scene.add(board);
    const traceGrid: number[] = [];
    for (let i = Math.ceil(-boardW * 2); i <= Math.floor(boardW * 2); i++) {
      const x = center.x + i * 0.25;
      traceGrid.push(
        x,
        -0.075,
        center.z - boardD / 2,
        x,
        -0.075,
        center.z + boardD / 2,
      );
    }
    for (let i = Math.ceil(-boardD * 2); i <= Math.floor(boardD * 2); i++) {
      const z = center.z + i * 0.25;
      traceGrid.push(
        center.x - boardW / 2,
        -0.075,
        z,
        center.x + boardW / 2,
        -0.075,
        z,
      );
    }
    const gridGeo = new THREE.BufferGeometry();
    gridGeo.setAttribute(
      "position",
      new THREE.Float32BufferAttribute(traceGrid, 3),
    );
    const gridMat = new THREE.LineBasicMaterial({
      color: dark ? "#9270ae" : "#9f8fae",
      transparent: true,
      opacity: dark ? 0.2 : 0.28,
      depthWrite: false,
      toneMapped: false,
    });
    scene.add(new THREE.LineSegments(gridGeo, gridMat));
    const collarGeo = new THREE.TorusGeometry(0.75, 0.022, 8, 60),
      collarMat = new THREE.MeshBasicMaterial({
        color: dark ? "#e1a9ff" : "#8753be",
        toneMapped: false,
      });
    const collar = new THREE.Mesh(collarGeo, collarMat);
    collar.rotation.x = Math.PI / 2;
    collar.visible = false;
    scene.add(collar);
    const edgeColors = dark
      ? { observed: "#c29bf9", declared: "#b6b0c1", inferred: "#e2a7db" }
      : { observed: "#6b41aa", declared: "#756d83", inferred: "#a151ac" };
    const wire = new THREE.MeshStandardMaterial({
      color: edgeColors.observed,
      metalness: 0.47,
      roughness: 0.34,
      emissive: edgeColors.observed,
      emissiveIntensity: 0.15,
    });
    const dashed = {
      declared: new THREE.LineDashedMaterial({
        color: edgeColors.declared,
        dashSize: 0.055,
        gapSize: 0.075,
        toneMapped: false,
      }),
      inferred: new THREE.LineDashedMaterial({
        color: edgeColors.inferred,
        dashSize: 0.17,
        gapSize: 0.09,
        toneMapped: false,
      }),
    };
    const headGeo = new THREE.ConeGeometry(0.079, 0.21, 6),
      headMaterials = Object.fromEntries(
        Object.entries(edgeColors).map(([k, c]) => [
          k,
          new THREE.MeshBasicMaterial({ color: c, toneMapped: false }),
        ]),
      );
    const edgeGeos: THREE.BufferGeometry[] = [];
    for (const e of layout.edges) {
      const startPoint = plot.get(e.source)?.position,
        endPoint = plot.get(e.target)?.position;
      if (!startPoint || !endPoint) continue;
      const start = startPoint.clone(),
        end = endPoint.clone(),
        delta = end.clone().sub(start),
        dir = delta.clone().normalize();
      if (e.source === e.target) {
        start.z += 0.36;
        end.x += 0.42;
      } else {
        start.addScaledVector(dir, 0.64);
        end.addScaledVector(dir, -0.66);
      }
      start.y = end.y = 0.2;
      const a = start.clone(),
        b = end.clone();
      if (e.source === e.target) {
        a.y = b.y = 0.76;
        a.z += 0.75;
        b.x += 0.68;
      } else {
        a.addScaledVector(dir, Math.min(0.72, delta.length() * 0.15));
        b.addScaledVector(dir, -Math.min(0.72, delta.length() * 0.15));
        a.y = b.y =
          e.relation === "declared"
            ? 0.36
            : e.relation === "inferred"
              ? 0.69
              : 0.53;
      }
      const curve = new THREE.CubicBezierCurve3(start, a, b, end);
      if (e.relation === "observed") {
        const geo = new THREE.TubeGeometry(curve, 26, 0.028, 7, false);
        edgeGeos.push(geo);
        scene.add(new THREE.Mesh(geo, wire));
      } else {
        const geo = new THREE.BufferGeometry().setFromPoints(
          curve.getPoints(28),
        );
        edgeGeos.push(geo);
        const line = new THREE.Line(geo, dashed[e.relation]);
        line.computeLineDistances();
        scene.add(line);
      }
      const head = new THREE.Mesh(headGeo, headMaterials[e.relation]);
      head.position.copy(curve.getPoint(0.9));
      head.quaternion.setFromUnitVectors(up, curve.getTangent(0.9).normalize());
      scene.add(head);
    }
    const draw = () => renderer.render(scene, camera);
    const eye = new THREE.Vector3(0.19, 1.02, 1.33).normalize();
    function fit() {
      camera.aspect =
        Math.max(1, host!.clientWidth) / Math.max(1, host!.clientHeight);
      camera.updateProjectionMatrix();
      const corners: THREE.Vector3[] = [];
      for (const x of [bounds.min.x - 1.12, bounds.max.x + 1.12])
        for (const z of [bounds.min.z - 0.85, bounds.max.z + 0.9])
          for (const y of [-0.1, 2.02])
            corners.push(new THREE.Vector3(x, y, z));
      const aim = center.clone();
      aim.y = 0.65;
      controls.target.copy(aim);
      const right = new THREE.Vector3().crossVectors(up, eye).normalize(),
        vertical = new THREE.Vector3().crossVectors(eye, right).normalize(),
        fov = Math.tan(THREE.MathUtils.degToRad(camera.fov / 2));
      let distance = 3.15;
      for (const c of corners) {
        const v = c.sub(aim);
        distance = Math.max(
          distance,
          v.dot(eye) +
            Math.max(
              Math.abs(v.dot(right)) / (fov * camera.aspect),
              Math.abs(v.dot(vertical)) / fov,
            ),
        );
      }
      camera.position.copy(aim).addScaledVector(eye, distance * 1.07);
      controls.update();
      draw();
    }
    function selectNode(id: string) {
      const obj = plot.get(id);
      collar.visible = !!obj;
      if (obj) {
        collar.position.copy(obj.position);
        collar.position.y = 0.15;
      }
      draw();
    }
    function execute(c: GraphCommand) {
      if (c.kind === "fit") {
        fit();
        return;
      }
      const direction = camera.position
        .clone()
        .sub(controls.target)
        .normalize();
      if (c.kind === "focus" && c.nodeId) {
        const obj = plot.get(c.nodeId);
        if (!obj) return;
        controls.target.copy(obj.position);
        controls.target.y = 0.58;
        camera.position.copy(controls.target).addScaledVector(direction, 4.45);
        controls.update();
        draw();
        return;
      }
      if (c.kind === "in" || c.kind === "out") {
        const distance = THREE.MathUtils.clamp(
          camera.position.distanceTo(controls.target) *
            (c.kind === "in" ? 0.77 : 1.3),
          controls.minDistance,
          controls.maxDistance,
        );
        camera.position
          .copy(controls.target)
          .addScaledVector(direction, distance);
        controls.update();
        draw();
      }
    }
    runtime.current = { command: execute, select: selectNode };
    controls.addEventListener("change", draw);
    const resize = () => {
      renderer.setSize(
        Math.max(1, host.clientWidth),
        Math.max(1, host.clientHeight),
      );
      camera.aspect = host.clientWidth / Math.max(1, host.clientHeight);
      camera.updateProjectionMatrix();
      draw();
    };
    const observer = new ResizeObserver(resize);
    observer.observe(host);
    resize();
    fit();
    selectNode(selection.current);
    let press = { x: 0, y: 0 };
    const down = (e: PointerEvent) => {
      press = { x: e.clientX, y: e.clientY };
    };
    const ray = new THREE.Raycaster();
    const pick = (e: PointerEvent) => {
      if (
        e.button !== 0 ||
        Math.hypot(e.clientX - press.x, e.clientY - press.y) > 5
      )
        return;
      const rect = renderer.domElement.getBoundingClientRect();
      ray.setFromCamera(
        new THREE.Vector2(
          ((e.clientX - rect.left) / rect.width) * 2 - 1,
          (-(e.clientY - rect.top) / rect.height) * 2 + 1,
        ),
        camera,
      );
      const hit = ray.intersectObjects(clickable, true)[0];
      if (hit) {
        const node = nodeRecords.get(hit.object.userData.nodeId);
        if (node) selectRef.current(node);
      }
    };
    const lost = (event: Event) => {
      event.preventDefault();
      setFailure(true);
    };
    renderer.domElement.addEventListener("pointerdown", down);
    renderer.domElement.addEventListener("pointerup", pick);
    renderer.domElement.addEventListener("webglcontextlost", lost);
    return () => {
      runtime.current = null;
      observer.disconnect();
      controls.removeEventListener("change", draw);
      controls.dispose();
      renderer.domElement.removeEventListener("pointerdown", down);
      renderer.domElement.removeEventListener("pointerup", pick);
      renderer.domElement.removeEventListener("webglcontextlost", lost);
      for (const s of labels) s.material.dispose();
      for (const tex of labelTextures) tex.dispose();
      [
        contact,
        environment,
        contactGeo,
        contactMat,
        substrateGeo,
        substrateMaterial,
        gridMat,
        gridGeo,
        collarMat,
        collarGeo,
        headGeo,
        wire,
        ...Object.values(headMaterials),
        ...Object.values(dashed),
        ...edgeGeos,
      ].forEach((value) => value.dispose());
      kit.dispose();
      scene.clear();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, [layout, mode]);
  useEffect(() => {
    runtime.current?.select(selected);
  }, [selected]);
  useEffect(() => {
    if (command) runtime.current?.command(command);
  }, [command]);
  return (
    <>
      <div ref={target} className="vgraph-three" aria-hidden="true" />
      {failure ? (
        <div className="vgraph-three-fallback" role="status">
          <Box size={26} />
          <strong>3D rendering unavailable</strong>
          <button type="button" onClick={onFallback}>
            Open 2D graph
          </button>
        </div>
      ) : (
        <span className="vgraph-orbit-tip">Drag to orbit · Scroll to zoom</span>
      )}
    </>
  );
}
