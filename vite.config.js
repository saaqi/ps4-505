import { defineConfig } from "vite";
import legacy from "@vitejs/plugin-legacy";
import { exec } from "child_process";
import path from "path";

function runPostBuildScripts() {
  return {
    name: "run-post-build-scripts",
    closeBundle() {
      const distPath = path.resolve(__dirname, "dist");

      if (process.platform === "win32") {
        exec(`cmd /c "${distPath}\\build.bat"`);
      } else {
        exec(`sh "${distPath}/build.sh"`);
      }
    },
  };
}

export default defineConfig({
  base: "./",
  plugins: [
    legacy({
      // THIS is what matters now
      targets: ["Safari >= 8"],
      renderLegacyChunks: true,
      polyfills: true,
      additionalLegacyPolyfills: ["regenerator-runtime/runtime"],
    }),
    runPostBuildScripts(),
  ],
  build: {
    minify: "terser",
    terserOptions: {
      ecma: 5,
    },
  },
});
