import { defineConfig } from "vite";

// The component workbench uses ordinary browser React, independent of the application Worker.
export default defineConfig({ publicDir: false });
