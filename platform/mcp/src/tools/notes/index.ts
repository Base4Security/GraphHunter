import type { Tool } from "../../lib/types.js";
import { createNote } from "./create_note.js";
import { getNotes } from "./get_notes.js";
import { getPathNodes } from "./get_path_nodes.js";
import { tagEntity } from "./tag_entity.js";
import { untagEntity } from "./untag_entity.js";
import { listTagged } from "./list_tagged.js";

export const notesTools: Tool[] = [
  createNote,
  getNotes,
  getPathNodes,
  tagEntity,
  untagEntity,
  listTagged,
];
