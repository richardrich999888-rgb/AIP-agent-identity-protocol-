import type { StorybookConfig } from "@storybook/react-vite";

const config: StorybookConfig = {
  stories: ["../design-review/*.stories.tsx"],
  framework: {
    name: "@storybook/react-vite",
    options: { builder: { viteConfigPath: ".storybook/vite.config.ts" } },
  },
  addons: ["@storybook/addon-a11y", "@storybook/addon-mcp"],
  staticDirs: [{ from: "../public/upstream-replay", to: "/upstream-replay" }],
  core: { disableTelemetry: true },
};
export default config;
