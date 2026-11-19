// Copyright (c) 2026, The Discrete developers
//
// Offline difficulty qualification using the linked Currency implementation.
// The numerical model below is not a miner or a blockchain replay. It models
// immediate propagation, exponential PoW work and template creation/refresh.
// Real Core admission, persistence and reorganization are tested separately.

#include "CryptoNoteCore/Currency.h"
#include "Logging/LoggerGroup.h"
#include "timestamp_lwma_vectors.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr uint64_t BASE = UINT64_C(1800000000);
constexpr uint64_t TARGET = 90;
constexpr uint64_t FUTURE_LIMIT = 270;
constexpr uint64_t WORK = UINT64_C(100000000);
constexpr size_t WINDOW = 60;
constexpr size_t MODEL_BLOCKS = 800;
constexpr uint32_t MODEL_SEEDS = 100;
constexpr std::array<double, 7> MODEL_HORIZONS{{60, 270, 900, 3600, 7200, 14400, 72000}};
size_t checks = 0;

void require(bool condition, const std::string& message) {
  ++checks;
  if (!condition) throw std::runtime_error(message);
}

uint64_t next(const CryptoNote::Currency& currency,
              const std::vector<uint64_t>& timestamps,
              const std::vector<uint64_t>& cumulativeWork,
              uint32_t height = 103324) {
  require(timestamps.size() == cumulativeWork.size(), "parallel LWMA input lengths");
  const size_t from = timestamps.size() > WINDOW + 1
                    ? timestamps.size() - WINDOW - 1 : 0;
  return currency.nextDifficulty(height, 1,
    {timestamps.begin() + static_cast<std::ptrdiff_t>(from), timestamps.end()},
    {cumulativeWork.begin() + static_cast<std::ptrdiff_t>(from), cumulativeWork.end()});
}

std::vector<uint64_t> initialTimes() {
  std::vector<uint64_t> result;
  for (size_t i = 0; i <= WINDOW; ++i) result.push_back(BASE - (WINDOW - i) * TARGET);
  return result;
}

std::vector<uint64_t> initialWork() {
  std::vector<uint64_t> result;
  for (size_t i = 0; i <= WINDOW; ++i) result.push_back((i + 1) * WORK);
  return result;
}

uint64_t medianFloor(const std::vector<uint64_t>& timestamps) {
  if (timestamps.size() < 11) return 0;
  std::array<uint64_t, 11> window{};
  std::copy(timestamps.end() - 11, timestamps.end(), window.begin());
  std::sort(window.begin(), window.end());
  return window[5];
}

double uniformOpen(std::mt19937_64& random) {
  // The integer-to-double conversion is explicitly specified rather than
  // relying on implementation-defined distribution adapters.
  return (static_cast<double>(random() >> 11) + 0.5) / 9007199254740992.0;
}

void historicalChecks(const CryptoNote::Currency& legacy,
                      const CryptoNote::Currency& activated) {
  const auto& source = TimestampLwmaVectors::historical;
  require(source.size() == 131, "historical fixture contains 131 headers");
  size_t matched = 0;
  size_t clampDifferences = 0;
  std::vector<uint64_t> timestamps, cumulativeWork, clamped;
  for (const auto& row : source) {
    require(timestamps.empty() || row.height == source[0].height + timestamps.size(),
            "historical fixture is contiguous and height-ordered");
    timestamps.push_back(row.timestamp);
    cumulativeWork.push_back(row.cumulativeDifficulty);
    clamped.push_back(std::max(row.timestamp, clamped.empty() ? uint64_t{0} : clamped.back()));
  }
  for (size_t i = WINDOW + 1; i < source.size(); ++i) {
    std::vector<uint64_t> ts(timestamps.begin() + i - WINDOW - 1, timestamps.begin() + i);
    std::vector<uint64_t> cd(cumulativeWork.begin() + i - WINDOW - 1, cumulativeWork.begin() + i);
    std::vector<uint64_t> monotonic(clamped.begin() + i - WINDOW - 1, clamped.begin() + i);
    const uint64_t before = next(legacy, ts, cd, source[i].height);
    const uint64_t after = next(activated, ts, cd, source[i].height);
    require(before == source[i].difficulty, "published difficulty at height " + std::to_string(source[i].height));
    require(after == before, "activation configuration leaves fixed historical LWMA inputs unchanged");
    if (next(activated, monotonic, cd, source[i].height) != before) ++clampDifferences;
    ++matched;
  }
  require(matched == 70, "70 published difficulty values reproduced by actual Currency");
  require(clampDifferences == 0, "sample-only fixed-work clamp retains 70 historical difficulties");
  std::cout << "HISTORICAL,matches," << matched << ",fixed_work_clamp_differences,"
            << clampDifferences << '\n';
}

void fixedInputChecks(const CryptoNote::Currency& legacy,
                      const CryptoNote::Currency& activated) {
  require(legacy.difficultyTarget() == TARGET, "target stays 90 seconds");
  require(legacy.difficultyBlocksCount4() == WINDOW, "LWMA window stays 60");
  require(legacy.timestampCheckWindow(1) == 11, "main timestamp median stays 11");
  require(legacy.blockFutureTimeLimit(1) == FUTURE_LIMIT, "future allowance stays 270 seconds");

  const auto cumulativeWork = initialWork();
  auto timestamps = initialTimes();
  // Independent golden arithmetic from the legacy formula: first interval is
  // 2*T, so L=T*(N*(N+1)/2+1), followed by existing decimal rounding.
  require(next(legacy, timestamps, cumulativeWork) == UINT64_C(98900000),
          "steady fixed-work legacy golden");
  std::fill(timestamps.begin(), timestamps.end(), BASE);
  // All equal values hit L=N*N*T/20; existing rounding yields this value.
  require(next(legacy, timestamps, cumulativeWork) == UINT64_C(1010000000),
          "equal-second plateau legacy golden");
  require(next(activated, timestamps, cumulativeWork) == next(legacy, timestamps, cumulativeWork),
          "equal-second plateau fixed inputs unchanged");
  for (size_t i = 0; i < timestamps.size(); ++i) timestamps[i] = BASE + i * 6000;
  require(next(legacy, timestamps, cumulativeWork) == UINT64_C(16500000),
          "large gaps preserve six-target interval cap");
  require(next(activated, timestamps, cumulativeWork) == next(legacy, timestamps, cumulativeWork),
          "large-gap fixed inputs unchanged");

  std::mt19937_64 random(0x4c574d412d666c6fULL);
  constexpr std::array<uint64_t, 5> scales{{1, 100000, 100000000, UINT64_C(1000000000000), UINT64_C(100000000000000)}};
  for (size_t sample = 0; sample < 10000; ++sample) {
    const size_t count = 1 + random() % (WINDOW + 1);
    std::vector<uint64_t> ts, cd;
    uint64_t work = 0;
    for (size_t i = 0; i < count; ++i) {
      const int64_t skew = static_cast<int64_t>(random() % 1201) - 600;
      ts.push_back(static_cast<uint64_t>(static_cast<int64_t>(BASE + i * (sample % 7)) + skew));
      work += scales[sample % scales.size()] + random() % 1000;
      cd.push_back(work);
    }
    const uint32_t height = static_cast<uint32_t>(sample + 1);
    const auto before = next(legacy, ts, cd, height);
    const auto after = next(activated, ts, cd, height);
    require(before == after, "fixed randomized LWMA inputs unchanged at sample " + std::to_string(sample));
    require(after >= CryptoNote::parameters::MINIMUM_DIFFICULTY, "mainnet difficulty floor retained");
  }
  std::cout << "FIXED_INPUTS,randomized_windows,10000,golden_cases,3\n";
}

enum class Policy { RawMtp, CurrentTemplate, ForkTemplate };

const char* name(Policy policy) {
  switch (policy) {
    case Policy::RawMtp: return "raw_mtp";
    case Policy::CurrentTemplate: return "current_template";
    case Policy::ForkTemplate: return "fork_template";
  }
  return "unknown";
}

struct Scenario {
  const char* name;
  std::array<int, 3> offsets;
  uint64_t tipLead;
  bool invertedBoundary;
  double burstMultiplier;
};

struct Point {
  double elapsed;
  uint64_t difficulty;
  uint64_t timestamp;
  double templateCreated;
  int offset;
};

struct Run {
  std::vector<Point> trace;
  uint64_t equalTimestampBlocks = 0;
  uint64_t periodicRefreshes = 0;
};

uint64_t templateTimestamp(const std::vector<uint64_t>& timestamps,
                           double created, int offset, Policy policy,
                           bool activationBlock) {
  uint64_t stamp = std::max(
    static_cast<uint64_t>(static_cast<int64_t>(BASE) + static_cast<int64_t>(std::floor(created)) + offset),
    medianFloor(timestamps));
  if (policy != Policy::RawMtp) stamp = std::max(stamp, timestamps.back());
  if (policy == Policy::ForkTemplate && activationBlock) {
    stamp = std::max(stamp, timestamps[timestamps.size() - 2]);
  }
  return stamp;
}

double solveAfter(double start, uint64_t difficulty, double exponentialDraw,
                  double burstMultiplier) {
  const double rate = static_cast<double>(WORK) / TARGET;
  const double demand = static_cast<double>(difficulty) * exponentialDraw;
  if (start < 60.0 && burstMultiplier != 1.0) {
    const double earlyCapacity = (60.0 - start) * rate * burstMultiplier;
    if (demand <= earlyCapacity) return start + demand / (rate * burstMultiplier);
    return 60.0 + (demand - earlyCapacity) / rate;
  }
  return start + demand / rate;
}

Run feedback(const CryptoNote::Currency& currency, const Scenario& scenario,
             uint32_t seed, Policy policy) {
  auto timestamps = initialTimes();
  auto cumulativeWork = initialWork();
  timestamps.back() += scenario.tipLead;
  if (scenario.invertedBoundary) {
    // At real time -90 the grandparent can be stamped +180: its lead was
    // exactly the existing +270 allowance. The old-rule parent steps back to 0.
    timestamps[timestamps.size() - 2] = BASE + 180;
  }
  std::mt19937_64 random(seed);
  Run result;
  double elapsed = 0;
  for (size_t i = 0; i < MODEL_BLOCKS; ++i) {
    const uint64_t difficulty = next(currency, timestamps, cumulativeWork);
    const double workDraw = -std::log1p(-uniformOpen(random));
    const size_t producer = static_cast<size_t>(random() % scenario.offsets.size());
    const int offset = scenario.offsets[producer];
    const double solved = solveAfter(elapsed, difficulty, workDraw, scenario.burstMultiplier);

    // Model an idle callback at every integer wall second, with the initial
    // callback at time 0. OnceInInterval(5) requires elapsed wall seconds >5,
    // hence periodic updates at 6,12,... for these fixed integer clock offsets.
    // A successful chain update also creates a fresh template immediately.
    // A worker switches instantly in this model. Real scheduling, nonce-loop
    // overhead, propagation, stale work and competing branches are not modeled.
    const double periodicBeforeSolve = std::floor(solved / 6.0) * 6.0;
    const double created = std::max(elapsed, periodicBeforeSolve);
    result.periodicRefreshes += static_cast<uint64_t>(std::floor(solved / 6.0) - std::floor(elapsed / 6.0));
    const uint64_t stamp = templateTimestamp(timestamps, created, offset, policy, i == 0);
    require(created <= solved, "timestamp comes from an existing template");
    require(stamp >= medianFloor(timestamps), "modeled block meets raw MTP");
    require(stamp <= BASE + static_cast<uint64_t>(std::floor(solved)) + FUTURE_LIMIT,
            "modeled block fits exact observer future bound");
    if (policy == Policy::ForkTemplate) {
      uint64_t floor = timestamps.back();
      if (i == 0) floor = std::max(floor, timestamps[timestamps.size() - 2]);
      require(stamp >= floor, "modeled fork template meets actual-ancestor floor");
    }
    if (stamp == timestamps.back()) ++result.equalTimestampBlocks;
    require(cumulativeWork.back() <= std::numeric_limits<uint64_t>::max() - difficulty,
            "model cumulative work does not overflow");
    cumulativeWork.push_back(cumulativeWork.back() + difficulty);
    timestamps.push_back(stamp);
    result.trace.push_back({solved, difficulty, stamp, created, offset});
    elapsed = solved;
  }
  return result;
}

bool sameTrace(const Run& a, const Run& b) {
  if (a.trace.size() != b.trace.size()) return false;
  for (size_t i = 0; i < a.trace.size(); ++i) {
    const auto& x = a.trace[i];
    const auto& y = b.trace[i];
    if (x.elapsed != y.elapsed || x.difficulty != y.difficulty ||
        x.timestamp != y.timestamp || x.templateCreated != y.templateCreated ||
        x.offset != y.offset) return false;
  }
  return true;
}

size_t blocksBy(const Run& run, double time) {
  return static_cast<size_t>(std::count_if(run.trace.begin(), run.trace.end(),
    [time](const Point& point) { return point.elapsed <= time; }));
}

struct Comparison {
  double peakDifference = -1;
  uint32_t peakSeed = 0;
  size_t peakBlock = 0;
  double elapsedSum = 0;
  double minimumElapsed = std::numeric_limits<double>::infinity();
  double maximumElapsed = -std::numeric_limits<double>::infinity();
  double peakNormalizedElapsed = -1;
  double peakNormalizedElapsedSeconds = 0;
  uint32_t peakElapsedSeed = 0;
  size_t peakElapsedBlock = 0;
  std::array<int64_t, MODEL_HORIZONS.size()> blockCountDifferenceSum{};
  std::array<int64_t, MODEL_HORIZONS.size()> minimumBlockCountDifference{};
  std::array<int64_t, MODEL_HORIZONS.size()> maximumBlockCountDifference{};
  std::array<uint32_t, MODEL_HORIZONS.size()> horizonSamples{};
  std::array<uint32_t, MODEL_HORIZONS.size()> nonzeroHorizonSamples{};
  Run worstReference;
  Run worstCandidate;
};

void accumulate(Comparison& summary, const Run& reference, const Run& candidate,
                uint32_t seed) {
  for (size_t i = 0; i < reference.trace.size(); ++i) {
    const double delta = std::abs(static_cast<double>(candidate.trace[i].difficulty) /
                                  static_cast<double>(reference.trace[i].difficulty) - 1.0);
    if (delta > summary.peakDifference) {
      summary.peakDifference = delta;
      summary.peakSeed = seed;
      summary.peakBlock = i + 1;
      summary.worstReference = reference;
      summary.worstCandidate = candidate;
    }
    const double elapsedSeconds = candidate.trace[i].elapsed - reference.trace[i].elapsed;
    const double normalizedElapsed = std::abs(elapsedSeconds / reference.trace[i].elapsed);
    if (normalizedElapsed > summary.peakNormalizedElapsed) {
      summary.peakNormalizedElapsed = normalizedElapsed;
      summary.peakNormalizedElapsedSeconds = elapsedSeconds;
      summary.peakElapsedSeed = seed;
      summary.peakElapsedBlock = i + 1;
    }
  }
  const double elapsed = candidate.trace.back().elapsed / reference.trace.back().elapsed - 1.0;
  summary.elapsedSum += elapsed;
  summary.minimumElapsed = std::min(summary.minimumElapsed, elapsed);
  summary.maximumElapsed = std::max(summary.maximumElapsed, elapsed);
  for (size_t i = 0; i < MODEL_HORIZONS.size(); ++i) {
    // A fixed block-count run cannot determine how many blocks would follow its
    // last event. Exclude a pair unless both runs cover the requested horizon.
    if (reference.trace.back().elapsed < MODEL_HORIZONS[i] ||
        candidate.trace.back().elapsed < MODEL_HORIZONS[i]) continue;
    const auto delta = static_cast<int64_t>(blocksBy(candidate, MODEL_HORIZONS[i]))
                     - static_cast<int64_t>(blocksBy(reference, MODEL_HORIZONS[i]));
    if (summary.horizonSamples[i] == 0) {
      summary.minimumBlockCountDifference[i] = delta;
      summary.maximumBlockCountDifference[i] = delta;
    } else {
      summary.minimumBlockCountDifference[i] = std::min(summary.minimumBlockCountDifference[i], delta);
      summary.maximumBlockCountDifference[i] = std::max(summary.maximumBlockCountDifference[i], delta);
    }
    summary.blockCountDifferenceSum[i] += delta;
    ++summary.horizonSamples[i];
    if (delta != 0) ++summary.nonzeroHorizonSamples[i];
  }
}

void reportingChecks() {
  const Run reference{{{50, WORK, BASE, 0, 0}, {100, WORK, BASE, 0, 0},
                       {80000, WORK, BASE, 0, 0}}};
  const Run candidate{{{70, WORK, BASE, 0, 0}, {300, WORK, BASE, 0, 0},
                       {80001, WORK, BASE, 0, 0}}};
  require(blocksBy(reference, 50) == 1, "horizon includes an event exactly at its boundary");
  Comparison comparison;
  accumulate(comparison, reference, candidate, 7);
  require(comparison.horizonSamples[0] == 1 && comparison.blockCountDifferenceSum[0] == -1 &&
          comparison.nonzeroHorizonSamples[0] == 1, "horizon reports signed count differences");
  require(comparison.peakNormalizedElapsed == 2.0 && comparison.peakNormalizedElapsedSeconds == 200 &&
          comparison.peakElapsedSeed == 7 && comparison.peakElapsedBlock == 2,
          "same-height elapsed peak retains its location and signed seconds");
  auto truncated = reference;
  truncated.trace.back().elapsed = 70000;
  accumulate(comparison, truncated, candidate, 8);
  require(comparison.horizonSamples[0] == 2 && comparison.horizonSamples.back() == 1,
          "a truncated pair contributes only to horizons covered by both runs");
}

void writeTrace(const std::filesystem::path& output, const Scenario& scenario,
                Policy referencePolicy, const Comparison& comparison) {
  if (output.empty()) return;
  const auto path = output / (std::string(scenario.name) + "_" + name(referencePolicy) + "_vs_fork.csv");
  require(!std::filesystem::exists(path), "refuse to overwrite a previous trace");
  std::ofstream file(path);
  require(static_cast<bool>(file), "open trace output");
  file << std::setprecision(17)
       << "seed,block,reference_elapsed,candidate_elapsed,reference_difficulty,candidate_difficulty,"
          "reference_timestamp,candidate_timestamp,reference_template_created,candidate_template_created,"
          "reference_offset,candidate_offset\n";
  for (size_t i = 0; i < comparison.worstReference.trace.size(); ++i) {
    const auto& a = comparison.worstReference.trace[i];
    const auto& b = comparison.worstCandidate.trace[i];
    file << comparison.peakSeed << ',' << i + 1 << ',' << a.elapsed << ',' << b.elapsed << ','
         << a.difficulty << ',' << b.difficulty << ',' << a.timestamp << ',' << b.timestamp << ','
         << a.templateCreated << ',' << b.templateCreated << ',' << a.offset << ',' << b.offset << '\n';
  }
  require(static_cast<bool>(file), "write trace output");
}

void printComparison(const Scenario& scenario, Policy reference, const Comparison& value) {
  std::cout << "MODEL," << scenario.name << ',' << name(reference) << ",fork_template,"
            << MODEL_SEEDS << ',' << MODEL_BLOCKS << ',' << value.peakDifference * 100.0 << ','
            << value.peakSeed << ',' << value.peakBlock << ','
            << value.elapsedSum * 100.0 / MODEL_SEEDS << ','
            << value.minimumElapsed * 100.0 << ',' << value.maximumElapsed * 100.0 << ','
            << value.peakNormalizedElapsed * 100.0 << ',' << value.peakNormalizedElapsedSeconds << ','
            << value.peakElapsedSeed << ',' << value.peakElapsedBlock << '\n';
  for (size_t i = 0; i < MODEL_HORIZONS.size(); ++i) {
    std::cout << "MODEL_HORIZON," << scenario.name << ',' << name(reference)
              << ",fork_template," << MODEL_HORIZONS[i] << ',' << value.horizonSamples[i] << ','
              << MODEL_SEEDS - value.horizonSamples[i] << ',' << value.nonzeroHorizonSamples[i] << ',';
    if (value.horizonSamples[i] == 0) {
      std::cout << "NA,NA,NA\n";
    } else {
      std::cout << static_cast<double>(value.blockCountDifferenceSum[i]) / value.horizonSamples[i] << ','
                << value.minimumBlockCountDifference[i] << ',' << value.maximumBlockCountDifference[i] << '\n';
    }
  }
}

void feedbackChecks(const CryptoNote::Currency& legacy,
                    const CryptoNote::Currency& activated,
                    const std::filesystem::path& output) {
  reportingChecks();
  const std::array<Scenario, 8> scenarios{{
    {"steady_exact", {{0, 0, 0}}, 0, false, 1},
    {"steady_offsets_120", {{-120, 0, 120}}, 0, false, 1},
    {"steady_offsets_270", {{-270, 0, 270}}, 0, false, 1},
    {"future_tip_270_steady", {{0, 0, 0}}, 270, false, 1},
    {"future_tip_270_burst_100", {{0, 0, 0}}, 270, false, 100},
    {"future_tip_270_burst_1000", {{0, 0, 0}}, 270, false, 1000},
    {"inverted_activation_steady", {{0, 0, 0}}, 0, true, 1},
    {"inverted_activation_burst_1000", {{0, 0, 0}}, 0, true, 1000}
  }};
  std::cout << "MODEL_ASSUMPTIONS,template_at_creation,integer_second_idle_callbacks,strict_elapsed_gt_5,"
               "immediate_chain_update,instant_worker_switch,exponential_work,no_propagation_or_stale_branches\n";
  std::cout << "MODEL_COLUMNS,scenario,reference,candidate,seeds,blocks_per_run,peak_same_height_difficulty_delta_pct,"
               "peak_seed,peak_block,mean_elapsed_delta_pct,min_elapsed_delta_pct,max_elapsed_delta_pct,"
               "peak_abs_same_height_elapsed_delta_pct,signed_elapsed_seconds_at_peak,peak_elapsed_seed,peak_elapsed_block\n";
  std::cout << "MODEL_HORIZON_COLUMNS,scenario,reference,candidate,horizon_seconds,eligible_pairs,excluded_pairs,"
               "nonzero_count_delta_pairs,mean_count_delta,min_count_delta,max_count_delta\n";
  uint64_t equivalences = 0;
  uint64_t equalTimestampBlocks = 0;
  for (const auto& scenario : scenarios) {
    Comparison rawComparison, currentComparison;
    for (uint32_t seed = 0; seed < MODEL_SEEDS; ++seed) {
      const auto raw = feedback(legacy, scenario, seed, Policy::RawMtp);
      const auto current = feedback(legacy, scenario, seed, Policy::CurrentTemplate);
      const auto candidate = feedback(activated, scenario, seed, Policy::ForkTemplate);
      if (!scenario.invertedBoundary) {
        require(sameTrace(current, candidate), "candidate matches current template model on monotonic starting ancestry");
        ++equivalences;
      }
      if (std::string(scenario.name) == "steady_exact") {
        require(sameTrace(raw, candidate), "exact-clock steady model has no artificial timestamp differences");
      }
      equalTimestampBlocks += candidate.equalTimestampBlocks;
      accumulate(rawComparison, raw, candidate, seed);
      accumulate(currentComparison, current, candidate, seed);
    }
    printComparison(scenario, Policy::RawMtp, rawComparison);
    printComparison(scenario, Policy::CurrentTemplate, currentComparison);
    writeTrace(output, scenario, Policy::RawMtp, rawComparison);
    writeTrace(output, scenario, Policy::CurrentTemplate, currentComparison);
  }
  require(equivalences == 600, "600 current/fork model equivalences on monotonic starting ancestry");
  require(equalTimestampBlocks > 0, "model exercises equal-time rapid blocks");
  std::cout << "MODEL_TOTALS,current_fork_equal_runs," << equivalences
            << ",equal_timestamp_candidate_blocks," << equalTimestampBlocks << '\n';
}

} // namespace

int main(int argc, char** argv) {
  try {
    std::filesystem::path output;
    bool fixedOnly = false;
    for (int i = 1; i < argc; ++i) {
      const std::string argument = argv[i];
      if (argument == "--fixed-inputs-only") fixedOnly = true;
      else if (argument == "--output-dir" && i + 1 < argc) output = argv[++i];
      else throw std::runtime_error("Usage: timestamp_lwma_tests [--fixed-inputs-only] [--output-dir NEW_DIRECTORY]");
    }
    if (!output.empty()) {
      require(!std::filesystem::exists(output), "trace directory must be new");
      require(std::filesystem::create_directories(output), "create trace directory");
    }
    Logging::LoggerGroup logger;
    auto legacy = CryptoNote::CurrencyBuilder(logger).currency();
    auto activated = CryptoNote::CurrencyBuilder(logger).monotonicTimestampHeight(2).currency();
    std::cout << std::setprecision(17);
    historicalChecks(legacy, activated);
    fixedInputChecks(legacy, activated);
    if (!fixedOnly) feedbackChecks(legacy, activated, output);
    std::cout << "PASS,checks," << checks << '\n';
    return 0;
  } catch (const std::exception& exception) {
    std::cerr << "FAIL," << exception.what() << '\n';
    return 1;
  }
}
