/// @file result.hpp
/// @brief Match result storage and JSON serialization.
///
/// Provides the MatchResultSet container used by the C ABI to hold
/// results from pattern matching, and a simple JSON serializer that
/// avoids external dependencies (no nlohmann, no rapidjson).

#ifndef GRAPHMATCH_RESULT_HPP
#define GRAPHMATCH_RESULT_HPP

#include "matcher.hpp"
#include "types.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace gm {

// ---------------------------------------------------------------------------
// MatchResultSet — owning container for results, used by C ABI.
// ---------------------------------------------------------------------------

class MatchResultSet {
public:
    MatchResultSet() = default;

    explicit MatchResultSet(std::vector<MatchResult> results)
        : results_(std::move(results)) {}

    uint32_t count() const noexcept {
        return static_cast<uint32_t>(results_.size());
    }

    /// Access a result's path. Returns pointer and sets path_len.
    const uint32_t* get_path(uint32_t idx, uint32_t& path_len) const noexcept {
        if (idx >= results_.size()) { path_len = 0; return nullptr; }
        path_len = static_cast<uint32_t>(results_[idx].path.size());
        return results_[idx].path.data();
    }

    /// Access a result's timestamps.
    const int64_t* get_timestamps(uint32_t idx) const noexcept {
        if (idx >= results_.size()) return nullptr;
        return results_[idx].timestamps.data();
    }

    /// Get anomaly score for a result.
    float get_score(uint32_t idx) const noexcept {
        if (idx >= results_.size()) return 0.0f;
        return results_[idx].anomaly_score;
    }

    /// Serialize all results to JSON string.
    /// Caller must free the returned string with gm_free_string().
    char* to_json() const {
        std::string json;
        json.reserve(results_.size() * 128);

        json += "[\n";
        for (size_t i = 0; i < results_.size(); ++i) {
            if (i > 0) json += ",\n";
            json += "  ";
            result_to_json(results_[i], json);
        }
        json += "\n]";

        // Allocate C-owned string
        char* out = static_cast<char*>(std::malloc(json.size() + 1));
        if (out) {
            std::memcpy(out, json.c_str(), json.size() + 1);
        }
        return out;
    }

    /// Access underlying results vector.
    const std::vector<MatchResult>& results() const noexcept { return results_; }

private:
    static void result_to_json(const MatchResult& r, std::string& json) {
        json += "{\"path\":[";
        for (size_t i = 0; i < r.path.size(); ++i) {
            if (i > 0) json += ',';
            json += std::to_string(r.path[i]);
        }
        json += "],\"timestamps\":[";
        for (size_t i = 0; i < r.timestamps.size(); ++i) {
            if (i > 0) json += ',';
            json += std::to_string(r.timestamps[i]);
        }
        json += "],\"anomaly_score\":";
        append_float(r.anomaly_score, json);
        json += ",\"match_confidence\":";
        append_float(r.match_confidence, json);
        json += '}';
    }

    static void append_float(float v, std::string& json) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.6f", static_cast<double>(v));
        json += buf;
    }

    std::vector<MatchResult> results_;
};

} // namespace gm

#endif // GRAPHMATCH_RESULT_HPP
