---
name: Sovereign Industrial
colors:
  surface: '#111317'
  surface-dim: '#111317'
  surface-bright: '#37393e'
  surface-container-lowest: '#0c0e12'
  surface-container-low: '#1a1c20'
  surface-container: '#1e2024'
  surface-container-high: '#282a2e'
  surface-container-highest: '#333539'
  on-surface: '#e2e2e8'
  on-surface-variant: '#b9cacb'
  inverse-surface: '#e2e2e8'
  inverse-on-surface: '#2f3035'
  outline: '#849495'
  outline-variant: '#3b494b'
  surface-tint: '#00dbe9'
  primary: '#dbfcff'
  on-primary: '#00363a'
  primary-container: '#00f0ff'
  on-primary-container: '#006970'
  inverse-primary: '#006970'
  secondary: '#d1bcff'
  on-secondary: '#3c0090'
  secondary-container: '#7000ff'
  on-secondary-container: '#ddcdff'
  tertiary: '#fff2f7'
  on-tertiary: '#5f004e'
  tertiary-container: '#ffcae9'
  on-tertiary-container: '#b00092'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#7df4ff'
  primary-fixed-dim: '#00dbe9'
  on-primary-fixed: '#002022'
  on-primary-fixed-variant: '#004f54'
  secondary-fixed: '#e9ddff'
  secondary-fixed-dim: '#d1bcff'
  on-secondary-fixed: '#23005b'
  on-secondary-fixed-variant: '#5700c9'
  tertiary-fixed: '#ffd8ed'
  tertiary-fixed-dim: '#ffade1'
  on-tertiary-fixed: '#3b002f'
  on-tertiary-fixed-variant: '#86006f'
  background: '#111317'
  on-background: '#e2e2e8'
  surface-variant: '#333539'
typography:
  display-lg:
    fontFamily: Chivo
    fontSize: 48px
    fontWeight: '900'
    lineHeight: '1.1'
    letterSpacing: -0.04em
  headline-lg:
    fontFamily: Chivo
    fontSize: 32px
    fontWeight: '700'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Chivo
    fontSize: 24px
    fontWeight: '700'
    lineHeight: '1.2'
  body-md:
    fontFamily: Hanken Grotesk
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.6'
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: '1.4'
    letterSpacing: 0.05em
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '700'
    lineHeight: '1.2'
spacing:
  unit: 4px
  gutter: 24px
  margin-desktop: 64px
  margin-mobile: 16px
  container-max: 1440px
---

## Brand & Style
The design system embodies the "Sovereign Industrial" ethos: a high-stakes, defense-grade aesthetic tailored for national-scale AI infrastructure. It projects an image of absolute stability, institutional authority, and futuristic precision. 

The visual language blends **Glassmorphism** with **Technical Minimalism**. It utilizes deep obsidian backgrounds to create a sense of infinite digital space, punctuated by high-energy electric gradients that represent active data intelligence. The interface should feel like a premium command-and-control center—utilitarian yet sophisticated, where every pixel serves a tactical purpose.

## Colors
The palette is rooted in **Obsidian Navy**, providing a low-light environment that reduces eye strain during long-term monitoring. 

- **Primary (Electric Cyan):** Used for critical data points, active states, and primary call-to-actions.
- **Secondary & Tertiary (Violet/Magenta):** Primarily utilized in gradients and data visualizations to indicate complex processing or multi-layered infrastructure.
- **Surface Navy:** Used for glassmorphic panel backgrounds to provide subtle contrast against the obsidian base.
- **Gradients:** Use linear gradients (45-degree angle) transitioning from Cyan to Violet or Violet to Magenta for decorative strokes and interactive headers.

## Typography
The typography strategy creates a hierarchy of "Command" and "Data."

**Chivo** is used for headlines, providing a sharp, high-contrast, and industrial feel. It should be used sparingly for maximum impact. **Hanken Grotesk** serves as the primary body face, offering modern legibility for long-form reports. **JetBrains Mono** is the "Technical Readout" font, used for all data values, labels, and system status messages to reinforce the engineering-first nature of the product. Use `label-caps` for all metadata and section headers.

## Layout & Spacing
The system utilizes a **Fixed Grid** on desktop and a **Fluid Grid** on mobile.

- **Grid:** A 12-column layout with 24px gutters. Elements should align strictly to the grid to maintain institutional order.
- **Rhythm:** An 8px linear scale is used for component spacing, while 4px increments are reserved for high-density data tables.
- **Lattice Overlays:** Large-scale background sections should feature a subtle 32px mathematical grid or dot-matrix pattern in low-opacity (#ffffff05) to evoke blueprint precision.
- **Safe Areas:** Maintain generous outer margins (64px+) on desktop to create a centered "Dashboard" feel.

## Elevation & Depth
Depth is achieved through layering and transparency rather than traditional drop shadows.

- **Glassmorphism:** Use background blurs (12px - 20px) on panels with a 40% opaque `#161b22` fill.
- **Gradient Strokes:** Panels are defined by 1px "Inner Glow" borders. These should use a subtle cyan-to-transparent gradient to simulate a backlit edge.
- **Tonal Tiers:** Level 0 is the Obsidian background. Level 1 is the primary container. Level 2 is for modals and pop-overs, which should have a slightly lighter fill and a more pronounced border glow.
- **Zero Shadows:** Do not use soft ambient shadows. Use high-contrast outlines to define object boundaries.

## Shapes
This design system uses a **Sharp (0px)** roundedness strategy. Every corner is a precise 90-degree angle to reinforce the "Industrial" and "Absolute" brand personality. 

The only exception to the sharp rule is for data visualization nodes (e.g., circular points in a network graph), which should remain perfect circles. All containers, buttons, and input fields must be strictly rectangular.

## Components
- **Buttons:** Primary buttons feature a solid Electric Cyan background with black text. Secondary buttons are transparent with a 1px Cyan stroke. Tertiary buttons are text-only using JetBrains Mono with a bracketed prefix (e.g., `[ EXECUTE ]`).
- **Inputs:** Underlined or fully boxed with 1px strokes. When focused, the stroke should pulse with a Cyan-to-Violet gradient.
- **Chips/Status:** Use JetBrains Mono. Status indicators should use small square icons (e.g., a green square for 'Operational', a red square for 'Critical').
- **Data Visualizations:** Use thin lines (0.5pt to 1pt). Avoid solid fills in charts; use diagonal hatch patterns or gradients with low opacity.
- **Cards/Panels:** Must include a "corner bracket" detail or a small monospaced ID tag in the top-right corner (e.g., `REF_0942`) to enhance the technical aesthetic.