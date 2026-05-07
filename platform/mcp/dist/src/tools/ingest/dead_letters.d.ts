export declare const ingestDeadLetters: import("../../lib/types.js").Tool<{
    op: "list" | "purge" | "retry";
    limit?: number | undefined;
    offset?: number | undefined;
    dataset_id?: string | undefined;
    failure_kind?: "parse_failure" | "invariant_causality" | "invariant_referential" | "invariant_type_shape" | "empty_yield" | "other" | undefined;
    all?: boolean | undefined;
    ids?: string[] | undefined;
}, unknown>;
//# sourceMappingURL=dead_letters.d.ts.map