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
      return pkg;
    },
  },
};
