/// @file csr_graph.cpp
/// @brief CSRTemporalGraph implementation — mostly header-only, this file
///        provides the explicit instantiation point for the linker.

#include "graphmatch/csr_graph.hpp"

// CSRTemporalGraph is currently header-only. This translation unit exists
// to ensure the header compiles cleanly as a standalone unit and to serve
// as the future home of any non-inline methods that grow too large for
// the header (e.g., serialization, statistics).

namespace gm {

// Reserved for future non-inline implementations.

} // namespace gm
