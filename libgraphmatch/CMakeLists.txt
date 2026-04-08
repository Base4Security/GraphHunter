cmake_minimum_required(VERSION 3.20)
project(libgraphmatch VERSION 0.1.0 LANGUAGES CXX)

# ── C++20, no exceptions, no RTTI ──────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler flags ─────────────────────────────────────────────────────────
# Global flags: optimization + AVX2. Exception/RTTI opt-out is per-target so
# test executables (which need doctest's throwing macros) can re-enable them.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-O3 -Wall -Wextra -Wpedantic)
    # SIMD: enable AVX2 by default on x86_64 (override with -DGMATCH_ARCH=native)
    set(GMATCH_ARCH "native" CACHE STRING "Architecture flag for -march")
    add_compile_options(-march=${GMATCH_ARCH})
elseif(MSVC)
    add_compile_options(/O2 /W4 /arch:AVX2)
endif()

# ── Sources ────────────────────────────────────────────────────────────────
set(GMATCH_SOURCES
    src/simd_intersect.cpp
    src/csr_graph.cpp
    src/pattern.cpp
    src/pruning.cpp
    src/matcher.cpp
    src/scorer.cpp
    src/result.cpp
    src/graphmatch_cabi.cpp
)

# ── Static library ─────────────────────────────────────────────────────────
add_library(graphmatch STATIC ${GMATCH_SOURCES})
target_include_directories(graphmatch PUBLIC include)
set_target_properties(graphmatch PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
# Library itself is built without exceptions/RTTI for size & codegen.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(graphmatch PRIVATE -fno-exceptions -fno-rtti)
elseif(MSVC)
    target_compile_options(graphmatch PRIVATE /EHs-c- /GR-)
endif()

# ── Tests (doctest) ────────────────────────────────────────────────────────
option(GMATCH_BUILD_TESTS "Build unit tests" ON)

if(GMATCH_BUILD_TESTS)
    enable_testing()

    # Test executables — each links against graphmatch
    set(TEST_SOURCES
        tests/test_simd_intersect.cpp
        tests/test_csr_graph.cpp
        tests/test_pruning.cpp
        tests/test_matcher.cpp
        tests/test_apt29_killchain.cpp
    )

    foreach(test_src ${TEST_SOURCES})
        get_filename_component(test_name ${test_src} NAME_WE)
        add_executable(${test_name} ${test_src})
        target_link_libraries(${test_name} PRIVATE graphmatch)
        target_include_directories(${test_name} PRIVATE tests)

        # Re-enable exceptions for doctest (test-only, not in the lib)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${test_name} PRIVATE -fexceptions)
        elseif(MSVC)
            target_compile_options(${test_name} PRIVATE /EHsc)
        endif()

        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()

# ── Benchmarks ─────────────────────────────────────────────────────────────
option(GMATCH_BUILD_BENCH "Build benchmarks" ON)

if(GMATCH_BUILD_BENCH)
    add_executable(bench_intersect bench/bench_intersect.cpp)
    target_link_libraries(bench_intersect PRIVATE graphmatch)
    target_include_directories(bench_intersect PRIVATE tests)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(bench_intersect PRIVATE -fexceptions)
    endif()

    add_executable(bench_matching bench/bench_matching.cpp)
    target_link_libraries(bench_matching PRIVATE graphmatch)
    target_include_directories(bench_matching PRIVATE tests)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(bench_matching PRIVATE -fexceptions)
    endif()
endif()

# ── Install ────────────────────────────────────────────────────────────────
install(TARGETS graphmatch
    ARCHIVE DESTINATION lib
)
install(DIRECTORY include/graphmatch DESTINATION include)
