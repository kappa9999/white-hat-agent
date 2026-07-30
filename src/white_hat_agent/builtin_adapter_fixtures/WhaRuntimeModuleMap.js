"use strict";

const OUTPUT_MARKER = "WHA_FRIDA_RUNTIME_MAP_V1 ";
const COLLECTION_LIMITS = Object.freeze({
  modules: 1024,
  imports: 4096,
  exports: 4096,
  dependencies: 1024,
});

function pointerString(value) {
  return value === null || value === undefined ? null : value.toString();
}

function moduleRecord(module) {
  return {
    name: module.name,
    path: module.path,
    base: pointerString(module.base),
    size: module.size,
  };
}

function importRecord(item) {
  return {
    type: item.type,
    name: item.name,
    module: item.module === undefined ? null : item.module,
    address: pointerString(item.address),
    slot: pointerString(item.slot),
  };
}

function exportRecord(item, mainBase) {
  return {
    type: item.type,
    name: item.name,
    address: pointerString(item.address),
    offset_from_main: pointerString(item.address.sub(mainBase)),
  };
}

function dependencyRecord(item) {
  return {
    name: item.name,
    type: item.type,
  };
}

const collectionErrors = [];

function collect(name, producer, mapper) {
  try {
    const values = producer();
    const limit = COLLECTION_LIMITS[name];
    return {
      total: values.length,
      returned: Math.min(values.length, limit),
      truncated: values.length > limit,
      items: values.slice(0, limit).map(mapper),
    };
  } catch (error) {
    collectionErrors.push({
      collection: name,
      error: String(error),
    });
    return {
      total: 0,
      returned: 0,
      truncated: false,
      items: [],
    };
  }
}

const mainModule = Process.mainModule;
const result = {
  schema_version: "1.0",
  producer: "frida-inject",
  execution_phase: "spawned-before-main",
  cleanup_strategy: "eternalize-then-pid-namespace-teardown",
  process: {
    arch: Process.arch,
    platform: Process.platform,
    pointer_size: Process.pointerSize,
    page_size: Process.pageSize,
    code_signing_policy: Process.codeSigningPolicy,
  },
  main_module: moduleRecord(mainModule),
  modules: collect("modules", () => Process.enumerateModules(), moduleRecord),
  imports: collect("imports", () => mainModule.enumerateImports(), importRecord),
  exports: collect("exports", () => mainModule.enumerateExports(), (item) =>
    exportRecord(item, mainModule.base),
  ),
  dependencies: collect(
    "dependencies",
    () => mainModule.enumerateDependencies(),
    dependencyRecord,
  ),
  collection_errors: collectionErrors,
};

console.log(OUTPUT_MARKER + JSON.stringify(result));
