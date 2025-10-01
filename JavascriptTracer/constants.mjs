/**
 * Common constants used for instrumentation and runtime.
 * CommonJS module to support inclusion by the CommonJS runtime module.
 */

export const VALID_SUFFIXES = [".js", ".ts", ".mjs"]
export const PLUGIN_SUFFIX = ".mw";
export const PLUGIN_SUFFIX_REGEX = /\.mw\.(js|ts|mjs)$/i;
export const NODE_MODULES_DIR_NAME = "node_modules"

export const COMPUTED_OFFSET_INDICATOR = "___computed___";
export const PRIMITIVE_INDICATOR = "___primitive___";

export const INSTR_MODULE_NAME = "$$instr";
export const FILE_ID_VAR_NAME = "$$fileId";
export const INSTR_VAR_PREFIX = "$$";

export const CHAINVARNAME = `${INSTR_VAR_PREFIX}vChain`;
export const CALLVARNAME = `${INSTR_VAR_PREFIX}vCall`;
export const THISVARNAME = `${INSTR_VAR_PREFIX}vThis`;
export const ARGSVARNAME = `${INSTR_VAR_PREFIX}vArgs`;
export const SWITCHLABELNAME = `${INSTR_VAR_PREFIX}vSwitchLabel`;
export const SWITCHFALLTHROUGHVARNAME = `${INSTR_VAR_PREFIX}vSwitchFallthrough`;
export const COMPUTEDVARNAME = `${INSTR_VAR_PREFIX}vComputed`;
export const TERNARYIDNAME = `${INSTR_VAR_PREFIX}vTernaryId`;