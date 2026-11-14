// typescript-eslint parses with TypeScript's JS API, which TypeScript 7 (native) no longer ships.
// Give the lint packages their own TypeScript 5 instead of the project's compiler.
const lintPackages = /^(@typescript-eslint\/|typescript-eslint$|ts-api-utils$)/;
module.exports = {
  hooks: {
    readPackage(pkg) {
      if (lintPackages.test(pkg.name) && pkg.peerDependencies?.typescript) {
        delete pkg.peerDependencies.typescript;
        pkg.dependencies = { ...pkg.dependencies, typescript: "5.9.3" };
      }
      // minimatch 7.0.0–11.0.0 has a glob-parts denial of service (GHSA-g3hv-75wg-m249).
      if (pkg.name === "@typescript-eslint/typescript-estree" && pkg.dependencies?.minimatch) {
        pkg.dependencies = { ...pkg.dependencies, minimatch: "11.0.3" };
      }
      // Its own dependency, held to a release as old as minimatch 11.0.3 itself.
      if (pkg.name === "minimatch" && pkg.version === "11.0.3") {
        pkg.dependencies = { ...pkg.dependencies, "@isaacs/nonrecursive-glob-match": "1.0.3" };
      }
      return pkg;
    },
  },
};
