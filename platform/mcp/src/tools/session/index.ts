import type { Tool } from "../../lib/types.js";
import { sessionCheck } from "./check.js";
import { sessionCreate, sessionList, sessionCurrent, sessionLoad, sessionSave } from "./manage.js";

export const sessionTools: Tool[] = [
  sessionCheck,
  sessionCreate,
  sessionList,
  sessionCurrent,
  sessionLoad,
  sessionSave,
];
