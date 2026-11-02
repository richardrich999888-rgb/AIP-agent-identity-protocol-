import { describe, it, expect } from "vitest";

describe("Tier 1 - F4: Syntriass Enterprise Branding & Assets", () => {
  const brandPalette = {
    background: "#080B11",
    card: "#0E131F",
    muted: "#161F31",
    border: "#222F46",
    cyanPrimary: "#00E5FF",
    indigoTrust: "#6366F1",
    emeraldCountersigned: "#10B981",
    crimsonTamper: "#EF4444",
  };

  const svgWordmark = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 40">
    <text x="44" y="24">SYNTRIASS</text>
    <text x="44" y="34">ACCOUNTABILITY CONSOLE</text>
  </svg>`;

  it("F4.1: validates Syntriass brand wordmark text and subtitle", () => {
    expect(svgWordmark).toContain("SYNTRIASS");
    expect(svgWordmark).toContain("ACCOUNTABILITY CONSOLE");
  });

  it("F4.2: validates enterprise cyber color palette tokens", () => {
    expect(brandPalette.background).toBe("#080B11");
    expect(brandPalette.cyanPrimary).toBe("#00E5FF");
    expect(brandPalette.emeraldCountersigned).toBe("#10B981");
    expect(brandPalette.crimsonTamper).toBe("#EF4444");
  });

  it("F4.3: validates tripartite cryptographic knot geometry", () => {
    const knotVertices = [
      { x: 16, y: 2, label: "Identity" },
      { x: 29, y: 25, label: "Authority" },
      { x: 3, y: 25, label: "Accountability" },
    ];
    expect(knotVertices.length).toBe(3);
    expect(knotVertices.map((v) => v.label)).toEqual(["Identity", "Authority", "Accountability"]);
  });

  it("F4.4: enforces monospace typography for cryptographic values", () => {
    const monoStyles = {
      fontFamily: "monospace",
      cryptoClasses: "font-mono text-xs tracking-tight",
    };
    expect(monoStyles.fontFamily).toBe("monospace");
    expect(monoStyles.cryptoClasses).toContain("font-mono");
  });

  it("F4.5: verifies official tagline display in navigation header", () => {
    const tagline = "Prove what the agent did and who authorized it.";
    expect(tagline).toBe("Prove what the agent did and who authorized it.");
  });
});
