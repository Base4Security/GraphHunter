import { enrichIp } from "./enrich_ip.js";
import { fileTicket } from "./file_ticket.js";
import { publishIocsToSentinel } from "./publish_iocs_to_sentinel.js";
export const integrationsTools = [enrichIp, fileTicket, publishIocsToSentinel];
