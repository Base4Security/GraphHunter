import { z } from "zod";
export declare const fieldConfigSchema: z.ZodObject<{
    mappings: z.ZodArray<z.ZodRecord<z.ZodString, z.ZodAny>, "many">;
}, "passthrough", z.ZodTypeAny, z.objectOutputType<{
    mappings: z.ZodArray<z.ZodRecord<z.ZodString, z.ZodAny>, "many">;
}, z.ZodTypeAny, "passthrough">, z.objectInputType<{
    mappings: z.ZodArray<z.ZodRecord<z.ZodString, z.ZodAny>, "many">;
}, z.ZodTypeAny, "passthrough">>;
//# sourceMappingURL=field_config_schema.d.ts.map