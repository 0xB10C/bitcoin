// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Research harness (not meant for CI): validate the "addrman pollution ceiling"
// q_max(G, H) claimed for the #34019 eclipse model against the real AddrMan.
//
//   q_max(G, H) = 0.5 * min(1, G/32) + 0.5 * min(1, G*(G+H)/1024)
//
// where G is the number of netgroups (/16s without asmap) the attacker has
// addresses in and H the number of honest source netgroups relaying them.
//
// Run individual cases from the build directory, e.g.
//   ./bin/test_bitcoin -t addrman_qmax_tests/qmax_mapping
// CSV output goes to $QMAX_OUT_DIR (default: the first existing of
// simulation_data, ../simulation_data, ../../../simulation_data, else cwd).
// Knobs: QMAX_REPS, QMAX_DRAWS, QMAX_FILLS (comma list), QMAX_G, QMAX_H,
// QMAX_KEYS, QMAX_SNAPSHOT_DIR.

#include <addrdb.h>
#include <addrman.h>
#include <addrman_impl.h>
#include <chainparams.h>
#include <compat/compat.h>
#include <hash.h>
#include <netaddress.h>
#include <netgroup.h>
#include <node/data/ip_asn.dat.h>
#include <random.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace std::literals;

namespace {

auto EMPTY_NETGROUPMAN{NetGroupManager::NoAsmap()};
constexpr int32_t NO_CHECKS{0};
constexpr int ADDRS_PER_PAIR{ADDRMAN_BUCKET_SIZE * 8};
constexpr uint16_t ATTACKER_PORT{8333};
// A fixed "now" so that every generated nTime is reproducible across runs.
constexpr NodeSeconds FIXED_NOW{std::chrono::seconds{1'750'000'000}};

// ---------------------------------------------------------------- env knobs

int EnvInt(const char* name, int def)
{
    const char* v{std::getenv(name)};
    return v ? std::atoi(v) : def;
}

std::vector<std::string> SplitCsv(const std::string& s)
{
    std::vector<std::string> out;
    std::stringstream ss{s};
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

std::vector<int> EnvIntList(const char* name, const std::vector<int>& def)
{
    const char* v{std::getenv(name)};
    if (!v) return def;
    std::vector<int> out;
    for (const auto& s : SplitCsv(v)) out.push_back(std::atoi(s.c_str()));
    return out;
}

fs::path OutDir()
{
    if (const char* v{std::getenv("QMAX_OUT_DIR")}) return fs::PathFromString(v);
    for (const char* cand : {"simulation_data", "../simulation_data", "../../../simulation_data"}) {
        if (fs::is_directory(fs::PathFromString(cand))) return fs::PathFromString(cand);
    }
    return fs::PathFromString(".");
}

// ---------------------------------------------------------------- RNG

FastRandomContext CellRng(const std::string& tag, int a, int b, int c, int d)
{
    return FastRandomContext{(HashWriter{} << tag << a << b << c << d).GetHash()};
}

// ---------------------------------------------------------------- addresses

using Group16 = uint16_t; // a.b.0.0/16 encoded as (a << 8) | b

CNetAddr IPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    const uint8_t bytes[4]{a, b, c, d};
    in_addr ia;
    std::memcpy(&ia, bytes, 4);
    return CNetAddr{ia};
}

CNetAddr GroupSource(Group16 g) { return IPv4(g >> 8, g & 0xff, 1, 1); }

CAddress MakeAddr(Group16 g, uint16_t host, NodeSeconds ntime, uint16_t port = ATTACKER_PORT)
{
    CAddress addr{CService{IPv4(g >> 8, g & 0xff, host >> 8, host & 0xff), port}, NODE_NETWORK};
    addr.nTime = ntime;
    return addr;
}

std::optional<Group16> Slash16Of(const CNetAddr& a)
{
    if (!a.IsIPv4()) return std::nullopt;
    return static_cast<Group16>(a.GetLinkedIPv4() >> 16);
}

Group16 DrawRoutableGroup(FastRandomContext& rng, std::set<Group16>& used)
{
    for (int tries{0}; tries < 1'000'000; ++tries) {
        const uint8_t a{static_cast<uint8_t>(1 + rng.randrange(223))};
        const uint8_t b{static_cast<uint8_t>(rng.randrange(256))};
        const Group16 g{static_cast<Group16>((a << 8) | b)};
        if (used.count(g)) continue;
        if (!GroupSource(g).IsRoutable()) continue;
        used.insert(g);
        return g;
    }
    throw std::runtime_error("no unused routable /16 found");
}

std::set<Group16> GroupsInAddrman(const AddrMan& am)
{
    std::set<Group16> out;
    for (const bool tried : {false, true}) {
        for (const auto& [info, pos] : am.GetEntries(tried)) {
            if (const auto g{Slash16Of(info)}) out.insert(*g);
            if (const auto g{Slash16Of(info.source)}) out.insert(*g);
        }
    }
    return out;
}

constexpr std::array<std::array<uint8_t, 3>, 12> BITPROJECTS_24S{{
    {45, 40, 98}, {103, 47, 56}, {173, 46, 87}, {206, 206, 109},      // AS12029
    {89, 106, 27}, {174, 140, 231}, {184, 174, 95}, {216, 107, 135},  // AS29798
    {66, 163, 223}, {103, 246, 186}, {123, 100, 246}, {203, 11, 72},  // AS401199
}};

bool IsBitprojects(const CNetAddr& a)
{
    if (!a.IsIPv4()) return false;
    const uint32_t slash24{a.GetLinkedIPv4() >> 8};
    for (const auto& p : BITPROJECTS_24S) {
        if (slash24 == ((uint32_t{p[0]} << 16) | (uint32_t{p[1]} << 8) | p[2])) return true;
    }
    return false;
}

using IsAttackerFn = std::function<bool(const CNetAddr&)>;

// ---------------------------------------------------------------- attacker

struct AttackerSpec {
    int G{0};
    int H{0};
    std::vector<Group16> groups;  // the attacker's own /16s (size G)
    std::vector<Group16> sources; // G own + H honest relayer /16s
    std::vector<bool> is_group;   // 65536 flags

    int S() const { return G + H; }
    bool Is(const CNetAddr& a) const
    {
        const auto g{Slash16Of(a)};
        return g && is_group[*g];
    }
};

AttackerSpec DrawAttacker(FastRandomContext& rng, int G, int H, const std::set<Group16>& forbidden)
{
    AttackerSpec spec;
    spec.G = G;
    spec.H = H;
    std::set<Group16> used{forbidden};
    for (int i{0}; i < G; ++i) spec.groups.push_back(DrawRoutableGroup(rng, used));
    spec.sources = spec.groups;
    for (int i{0}; i < H; ++i) spec.sources.push_back(DrawRoutableGroup(rng, used));
    spec.is_group.assign(65536, false);
    for (const auto g : spec.groups) spec.is_group[g] = true;
    return spec;
}

//! Announce `per_pair` distinct attacker addresses for every (attacker group,
//! source group) pair. Each address is announced exactly once, from exactly one
//! source, so it ends up with nRefCount == 1 and cannot be displaced by honest
//! gossip (AddSingle only evicts terrible or multiply-referenced entries).
size_t InjectAttackerNew(AddrMan& am, const AttackerSpec& spec, NodeSeconds now, int per_pair)
{
    BOOST_REQUIRE(static_cast<size_t>(spec.S()) * per_pair < 65536);
    size_t attempted{0};
    for (const auto g : spec.groups) {
        for (size_t si{0}; si < spec.sources.size(); ++si) {
            std::vector<CAddress> batch;
            batch.reserve(per_pair);
            for (int i{0}; i < per_pair; ++i) {
                batch.push_back(MakeAddr(g, static_cast<uint16_t>(si * per_pair + i + 1), now));
            }
            am.Add(batch, GroupSource(spec.sources[si]));
            attempted += batch.size();
        }
    }
    return attempted;
}

// ---------------------------------------------------------------- honest background

struct BackgroundSpec {
    std::string name;
    int target_new;      // occupied new-table slots to aim for
    int target_tried;    // tried entries to aim for
    int honest_groups;   // distinct honest /16s
    int honest_sources;  // distinct honest source /16s
    int reannounce_k;    // number of announcement passes (multiplicity driver)
    double stale_frac;   // fraction of honest addresses older than the 30 d horizon
    double defended_frac; // fraction of honest tried entries with a success < 4 h ago
};

const std::vector<BackgroundSpec> FILLS{
    {"sparse", 2000, 100, 400, 40, 1, 0.3, 0.0},
    {"medium", 20000, 2000, 2000, 150, 2, 0.3, 0.0},
    {"saturated", 65536, 8000, 6000, 300, 3, 0.3, 0.0},
};

DataStream SerializeAddrman(const AddrMan& am)
{
    DataStream ss{};
    ss << Params().MessageStart();
    ss << am;
    return ss;
}

std::unique_ptr<AddrMan> FreshFromBytes(const DataStream& bytes, const NetGroupManager& ngm)
{
    auto am{std::make_unique<AddrMan>(ngm, /*deterministic=*/true, NO_CHECKS)};
    DataStream copy{std::span<const std::byte>{bytes.data(), bytes.size()}};
    ReadFromStream(*am, copy);
    return am;
}

DataStream BuildSyntheticBackground(const BackgroundSpec& spec, FastRandomContext& rng, NodeSeconds now)
{
    AddrMan am{EMPTY_NETGROUPMAN, /*deterministic=*/true, NO_CHECKS};
    std::set<Group16> used;
    std::vector<Group16> groups, sources;
    for (int i{0}; i < spec.honest_groups; ++i) groups.push_back(DrawRoutableGroup(rng, used));
    for (int i{0}; i < spec.honest_sources; ++i) sources.push_back(DrawRoutableGroup(rng, used));

    std::vector<CAddress> inserted;
    std::set<std::pair<Group16, uint16_t>> seen;
    constexpr size_t MAX_ATTEMPTS{400'000};
    constexpr int BATCH{100};
    size_t attempts{0};
    size_t slots{0};
    int batches{0};
    while (attempts < MAX_ATTEMPTS && slots < static_cast<size_t>(spec.target_new)) {
        const Group16 src{sources[rng.randrange(sources.size())]};
        std::vector<CAddress> batch;
        for (int i{0}; i < BATCH; ++i) {
            const Group16 g{groups[rng.randrange(groups.size())]};
            const auto host{static_cast<uint16_t>(1 + rng.randrange(65535))};
            if (!seen.insert({g, host}).second) continue;
            const bool stale{static_cast<double>(rng.randrange(1000)) < spec.stale_frac * 1000};
            const NodeSeconds t{stale ? now - 31 * 24h - std::chrono::seconds{rng.randrange(10 * 24 * 3600)}
                                      : now - std::chrono::seconds{rng.randrange(20 * 24 * 3600)}};
            batch.push_back(MakeAddr(g, host, t));
        }
        am.Add(batch, GroupSource(src));
        inserted.insert(inserted.end(), batch.begin(), batch.end());
        attempts += batch.size();
        if (++batches % 50 == 0) slots = am.GetEntries(false).size();
    }

    // Re-announcement passes from other sources with a strictly newer nTime
    // (AddSingle refuses otherwise), driving nRefCount > 1 for a subset.
    for (int pass{1}; pass < spec.reannounce_k; ++pass) {
        std::map<Group16, std::vector<CAddress>> by_source;
        for (const auto& a : inserted) {
            if (rng.randbool()) continue;
            CAddress b{a};
            b.nTime = a.nTime + pass * 1h;
            by_source[sources[rng.randrange(sources.size())]].push_back(b);
        }
        for (const auto& [src, batch] : by_source) am.Add(batch, GroupSource(src));
    }

    // Move a random subset to tried. Good() with an old success time means the
    // entry neither defends its slot (< 4 h rule) nor blocks a collision
    // resolution (> 40 min rule), so ResolveCollisions() settles immediately.
    const int max_goods{spec.target_tried * 4};
    for (int i{0}; i < max_goods && am.Size(std::nullopt, /*in_new=*/false) < static_cast<size_t>(spec.target_tried); ++i) {
        const CAddress& a{inserted[rng.randrange(inserted.size())]};
        const bool defended{static_cast<double>(rng.randrange(1000)) < spec.defended_frac * 1000};
        const NodeSeconds t{defended ? now - 1h : now - 5h - std::chrono::seconds{rng.randrange(20 * 24 * 3600)}};
        am.Good(a, t);
        if (i % 8 == 7) am.ResolveCollisions();
    }
    am.ResolveCollisions();
    return SerializeAddrman(am);
}

std::optional<DataStream> LoadSnapshotBytes(const fs::path& path)
{
    std::ifstream f{fs::PathToString(path), std::ios::binary};
    if (!f) return std::nullopt;
    std::vector<uint8_t> buf{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    return DataStream{std::span<const uint8_t>{buf}};
}

NodeSeconds YoungestNTime(const AddrMan& am)
{
    NodeSeconds youngest{0s};
    for (const bool tried : {false, true}) {
        for (const auto& [info, pos] : am.GetEntries(tried)) youngest = std::max(youngest, info.nTime);
    }
    return youngest;
}

// ---------------------------------------------------------------- measurement

struct SlotMass {
    bool att;
    double mass;   // exact probability that Select_'s bucket+position walk lands here
    double chance; // AddrInfo::GetChance(now)
};

struct TableStats {
    int n_buckets{0};
    int n_nonempty{0};
    int b_att{0};              // buckets holding >= 1 attacker entry
    int slots_total{0};
    int slots_att{0};
    double own_frac{0};        // mean attacker occupancy (of 64) over attacker buckets
    double honest_displaceable{0}; // honest slots that are terrible or multiply referenced
    int honest_mult_gt1{0};
    int honest_terrible{0};
    double q_mass{0};          // attacker share before GetChance()
    double q_chance{0};        // attacker share of accepted draws (exact)
};

//! Exact acceptance chain of Select_: each round lands on slot e with prob
//! mass_e and accepts with min(1, chance_e * 1.2^k); on rejection the chance
//! factor grows and a new bucket is drawn.
double ChanceAdjustedShare(const std::vector<SlotMass>& m)
{
    double p_att{0}, remaining{1}, cf{1.0};
    for (int k{0}; k < 100000 && remaining > 1e-15; ++k) {
        double a{0}, a_att{0};
        for (const auto& e : m) {
            const double acc{std::min(1.0, e.chance * cf)};
            a += e.mass * acc;
            if (e.att) a_att += e.mass * acc;
        }
        p_att += remaining * a_att;
        remaining *= (1 - a);
        cf *= 1.2;
    }
    return p_att;
}

TableStats MeasureTable(const AddrMan& am, bool tried, const IsAttackerFn& is_att, NodeSeconds now)
{
    TableStats st;
    st.n_buckets = tried ? ADDRMAN_TRIED_BUCKET_COUNT : ADDRMAN_NEW_BUCKET_COUNT;
    const int B{ADDRMAN_BUCKET_SIZE};
    std::vector<int8_t> occ(st.n_buckets * B, -1);
    std::vector<double> chance(st.n_buckets * B, 0.0);

    int honest_slots{0};
    for (const auto& [info, pos] : am.GetEntries(tried)) {
        const int idx{pos.bucket * B + pos.position};
        BOOST_REQUIRE(occ[idx] == -1);
        const bool att{is_att(info)};
        occ[idx] = att ? 1 : 0;
        chance[idx] = info.GetChance(now);
        ++st.slots_total;
        if (att) {
            ++st.slots_att;
        } else {
            ++honest_slots;
            const bool mult{pos.multiplicity > 1};
            const bool terrible{info.IsTerrible(now)};
            if (mult) ++st.honest_mult_gt1;
            if (terrible) ++st.honest_terrible;
            if (mult || terrible) st.honest_displaceable += 1;
        }
    }
    if (honest_slots > 0) st.honest_displaceable /= honest_slots;

    std::vector<int> nonempty;
    for (int b{0}; b < st.n_buckets; ++b) {
        for (int p{0}; p < B; ++p) {
            if (occ[b * B + p] >= 0) {
                nonempty.push_back(b);
                break;
            }
        }
    }
    st.n_nonempty = nonempty.size();

    std::vector<SlotMass> masses;
    double own_sum{0};
    for (const int b : nonempty) {
        int weight_sum{0};
        int att_in_bucket{0};
        for (int p{0}; p < B; ++p) {
            if (occ[b * B + p] < 0) continue;
            int gap{0};
            int q{(p + B - 1) % B};
            while (occ[b * B + q] < 0) {
                ++gap;
                q = (q + B - 1) % B;
            }
            weight_sum += 1 + gap;
            const double mass{static_cast<double>(1 + gap) / B / st.n_nonempty};
            const bool att{occ[b * B + p] == 1};
            if (att) {
                ++att_in_bucket;
                st.q_mass += mass;
            }
            masses.push_back({att, mass, chance[b * B + p]});
        }
        BOOST_REQUIRE_EQUAL(weight_sum, B);
        if (att_in_bucket > 0) {
            ++st.b_att;
            own_sum += static_cast<double>(att_in_bucket) / B;
        }
    }
    if (st.b_att > 0) st.own_frac = own_sum / st.b_att;
    st.q_chance = masses.empty() ? 0.0 : ChanceAdjustedShare(masses);
    return st;
}

double SampleSelect(const AddrMan& am, bool new_only, const IsAttackerFn& is_att, int draws)
{
    int hits{0};
    for (int i{0}; i < draws; ++i) {
        const auto [addr, last_try] = am.Select(new_only);
        if (is_att(addr)) ++hits;
    }
    return static_cast<double>(hits) / draws;
}

// ---------------------------------------------------------------- formulas

double F_linear(int G, int S) { return std::min(1024.0, 1.0 * G * S); }
double F_bday1024(int G, int S) { return 1024.0 * (1 - std::pow(1 - 1.0 / 1024, 1.0 * G * S)); }
double F_twostage(int G, int S)
{
    const double per_source{64.0 * (1 - std::pow(63.0 / 64, G))};
    return 1024.0 * (1 - std::pow(1 - 1.0 / 1024, S * per_source));
}
double T_linear(int G) { return std::min(256.0, 8.0 * G); }
double T_bday256(int G) { return 256.0 * (1 - std::pow(255.0 / 256, 8.0 * G)); }
double Q_prompt(int G, int S) { return 0.5 * std::min(1.0, G / 32.0) + 0.5 * std::min(1.0, 1.0 * G * S / 1024); }
double Q_prompt_bday(int G, int S) { return 0.5 * std::min(1.0, G / 32.0) + 0.5 * F_bday1024(G, S) / 1024; }

// ---------------------------------------------------------------- output

class CsvWriter
{
    std::ofstream m_f;
    fs::path m_path;

public:
    CsvWriter(const fs::path& path, const std::string& header) : m_f{fs::PathToString(path)}, m_path{path}
    {
        BOOST_REQUIRE_MESSAGE(m_f.good(), "cannot open " + fs::PathToString(path));
        m_f << header << "\n";
        std::cout << "writing " << fs::PathToString(path) << "\n";
    }
    void Row(const std::vector<std::string>& cells)
    {
        for (size_t i{0}; i < cells.size(); ++i) m_f << (i ? "," : "") << cells[i];
        m_f << "\n";
        m_f.flush();
    }
};

std::string D(double v, int prec = 5) { return strprintf("%.*f", prec, v); }
std::string I(long long v) { return strprintf("%d", v); }

const std::string CAPACITY_HEADER{
    "mode,fill,regime,rep,G,H,S,new_slots,tried_slots,new_nonempty,tried_nonempty,"
    "B_att_new,att_slots_new,own_frac,honest_displaceable,honest_mult_gt1,honest_terrible,"
    "q_new_mass,q_new_chance,q_new_sampled,B_att_tried,q_tried_chance,q_full_exact,q_full_sampled,"
    "forced_table,F1_linear,F2_bday1024,F3_twostage,q_prompt,q_prompt_bday,q_corrected,adds_attempted,draws"};

struct CapacityCellArgs {
    std::string mode;
    std::string fill;
    std::string regime;
    int rep;
    int G;
    int H;
    const DataStream* background;
    const NetGroupManager* ngm;
    const std::set<Group16>* forbidden;
    NodeSeconds now;
    int draws;
};

void RunCapacityCell(CsvWriter& csv, const CapacityCellArgs& a)
{
    auto am{FreshFromBytes(*a.background, *a.ngm)};
    FastRandomContext rng{CellRng(a.mode + "/" + a.fill + "/" + a.regime, a.G, a.H, a.rep, 0)};
    const AttackerSpec spec{DrawAttacker(rng, a.G, a.H, *a.forbidden)};
    const IsAttackerFn is_att{[&spec](const CNetAddr& addr) { return spec.Is(addr); }};

    const size_t attempted{InjectAttackerNew(*am, spec, a.now, ADDRS_PER_PAIR)};
    const TableStats tn{MeasureTable(*am, /*tried=*/false, is_att, a.now)};
    const TableStats tt{MeasureTable(*am, /*tried=*/true, is_att, a.now)};
    const double q_new_s{SampleSelect(*am, /*new_only=*/true, is_att, a.draws)};
    const double q_full_s{SampleSelect(*am, /*new_only=*/false, is_att, a.draws)};

    const bool both{tn.slots_total > 0 && tt.slots_total > 0};
    const std::string forced{both ? "none" : (tt.slots_total > 0 ? "tried" : "new")};
    const double q_full_exact{both ? 0.5 * (tn.q_chance + tt.q_chance) : (tt.slots_total > 0 ? tt.q_chance : tn.q_chance)};
    const double q_corrected{0.5 * (tn.n_nonempty ? static_cast<double>(tn.b_att) / tn.n_nonempty * tn.own_frac : 0.0) +
                             0.5 * (tt.n_nonempty ? static_cast<double>(tt.b_att) / tt.n_nonempty * tt.own_frac : 0.0)};

    // Structural invariants.
    BOOST_CHECK_LE(tn.b_att, static_cast<int>(F_linear(a.G, spec.S())));
    BOOST_CHECK_LE(tn.slots_att, ADDRMAN_BUCKET_SIZE * tn.b_att);
    BOOST_CHECK_EQUAL(tt.slots_att, 0);
    // Exact vs sampled agreement (6 sigma + a small absolute slack).
    const double sd{std::sqrt(std::max(tn.q_chance * (1 - tn.q_chance), 1e-6) / a.draws)};
    BOOST_CHECK_MESSAGE(std::abs(q_new_s - tn.q_chance) < 6 * sd + 0.002,
                        strprintf("%s/%s G=%d H=%d: sampled %.4f vs exact %.4f (sd %.4f)", a.fill, a.regime, a.G, a.H, q_new_s, tn.q_chance, sd));

    csv.Row({a.mode, a.fill, a.regime, I(a.rep), I(a.G), I(a.H), I(spec.S()), I(tn.slots_total), I(tt.slots_total),
             I(tn.n_nonempty), I(tt.n_nonempty), I(tn.b_att), I(tn.slots_att), D(tn.own_frac, 4), D(tn.honest_displaceable, 4),
             I(tn.honest_mult_gt1), I(tn.honest_terrible), D(tn.q_mass), D(tn.q_chance), D(q_new_s), I(tt.b_att), D(tt.q_chance),
             D(q_full_exact), D(q_full_s), forced, D(F_linear(a.G, spec.S()), 1), D(F_bday1024(a.G, spec.S()), 1),
             D(F_twostage(a.G, spec.S()), 1), D(Q_prompt(a.G, spec.S())), D(Q_prompt_bday(a.G, spec.S())), D(q_corrected),
             I(attempted), I(a.draws)});
    std::cout << strprintf("%-9s %-13s rep%d G=%2d H=%2d | new: nonempty %4d B_att %4d (F3 %6.1f) own %.2f | q_new exact %.4f sampled %.4f | q_prompt(new half) %.4f\n",
                           a.fill, a.regime, a.rep, a.G, a.H, tn.n_nonempty, tn.b_att, F_twostage(a.G, spec.S()), tn.own_frac,
                           tn.q_chance, q_new_s, std::min(1.0, 1.0 * a.G * spec.S() / 1024));
}

// ---------------------------------------------------------------- snapshots

struct Snapshot {
    std::string name;
    bool asmap; // the node ran with the embedded asmap
    int exp_new;
    int exp_tried;
    int exp_bp_new;
    int exp_bp_tried;
    std::vector<std::string> extra_candidates; // "$HOME/..." allowed
};

// Expected slot counts come from the simulation_34019.cpp harness on branch
// 2026-06-simulations-34019 (GetEntries().size() per table, Bitprojects slots).
const std::vector<Snapshot> SNAPSHOTS{
    {"2026-03-12-hal", true, 62183, 9413, 396, 371, {"$HOME/peers.dat"}},
    {"2026-06-24-cha", false, 65535, 9991, 2, 1295, {"$HOME/2026-06-24-cha-peers.dat"}},
    {"2025-04-24-dan", false, 51377, 199, 282, 3, {}},
    {"2025-08-15-dea", false, 65424, 3915, 610, 424, {}},
    {"2026-01-14-dar", false, 27563, 167, 884, 41, {}},
    {"2026-02-10-dan", false, 48755, 83, 1717, 19, {}},
    {"2026-03-15-dea", false, 65333, 8361, 1291, 1124, {}},
    {"2026-03-26-wil", false, 65170, 7902, 1419, 288, {}},
    {"2026-04-03-dar", false, 26945, 35, 803, 1, {}},
};

std::string ExpandHome(const std::string& s)
{
    if (s.rfind("$HOME/", 0) != 0) return s;
    const char* home{std::getenv("HOME")};
    return (home ? std::string{home} : std::string{"."}) + s.substr(5);
}

std::optional<fs::path> FindSnapshot(const Snapshot& snap)
{
    std::vector<std::string> cands;
    if (const char* d{std::getenv("QMAX_SNAPSHOT_DIR")}) cands.push_back(std::string{d} + "/" + snap.name + "-peers.dat");
    for (const char* dir : {"simulation_data", "../simulation_data", "../../../simulation_data"}) {
        cands.push_back(std::string{dir} + "/" + snap.name + "-peers.dat");
    }
    cands.push_back("$HOME/" + snap.name + "-peers.dat");
    for (const auto& c : snap.extra_candidates) cands.push_back(c);
    for (const auto& c : cands) {
        const fs::path p{fs::PathFromString(ExpandHome(c))};
        if (fs::exists(p)) return p;
    }
    return std::nullopt;
}

//! Parse "# q raw:" / "# q measured:" from an existing <name>-peers_results.txt.
std::pair<double, double> ParseResultsTxt(const std::string& name)
{
    for (const char* dir : {"simulation_data", "../simulation_data", "../../../simulation_data"}) {
        std::ifstream f{std::string{dir} + "/" + name + "-peers_results.txt"};
        if (!f) continue;
        double raw{-1}, measured{-1};
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("# q raw:", 0) == 0) raw = std::atof(line.c_str() + 8);
            if (line.rfind("# q measured:", 0) == 0) measured = std::atof(line.c_str() + 13);
        }
        return {raw, measured};
    }
    return {-1, -1};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(addrman_qmax_tests, BasicTestingSetup)

// 1. Pure hashing: how many distinct new/tried buckets can G attacker groups
//    reach via S source groups, versus the candidate formulas.
BOOST_AUTO_TEST_CASE(qmax_mapping)
{
    const int keys{EnvInt("QMAX_KEYS", 20)};
    const auto g_grid{EnvIntList("QMAX_G", {1, 2, 4, 8, 12, 16, 25})};
    const auto h_grid{EnvIntList("QMAX_H", {0, 10, 32, 64})};
    CsvWriter csv{OutDir() / "qmax_mapping.csv",
                  "key,G,H,S,new_distinct,stage64_pairs,F1_linear,F2_bday1024,F3_twostage,tried_distinct,tried_per_group_max,T1_linear,T2_bday256"};

    struct Agg {
        int n{0};
        double s{0}, s2{0}, st{0}, st2{0}, sp{0};
    };
    std::map<std::pair<int, int>, Agg> agg;

    for (int k{0}; k < keys; ++k) {
        const uint256 nKey{k == 0 ? uint256{1} : (HashWriter{} << k).GetHash()};
        for (const int G : g_grid) {
            for (const int H : h_grid) {
                FastRandomContext rng{CellRng("map", G, H, k, 0)};
                std::set<Group16> used;
                std::vector<Group16> groups, sources;
                for (int i{0}; i < G; ++i) groups.push_back(DrawRoutableGroup(rng, used));
                sources = groups;
                for (int i{0}; i < H; ++i) sources.push_back(DrawRoutableGroup(rng, used));
                const int S{G + H};

                std::set<int> new_buckets;
                std::set<std::pair<Group16, int>> stage64;
                for (const auto g : groups) {
                    const AddrInfo info{MakeAddr(g, 0x0101, FIXED_NOW), CNetAddr{}};
                    for (const auto s : sources) {
                        const CNetAddr src{GroupSource(s)};
                        new_buckets.insert(info.GetNewBucket(nKey, src, EMPTY_NETGROUPMAN));
                        // Mirror of AddrInfo::GetNewBucket's first stage.
                        const uint64_t hash1{(HashWriter{} << nKey << EMPTY_NETGROUPMAN.GetGroup(info) << EMPTY_NETGROUPMAN.GetGroup(src)).GetCheapHash()};
                        stage64.insert({s, static_cast<int>(hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)});
                    }
                }
                std::set<int> tried_buckets;
                size_t per_group_max{0};
                for (const auto g : groups) {
                    std::set<int> per;
                    for (uint16_t host{1}; host <= 128; ++host) {
                        const AddrInfo info{MakeAddr(g, host, FIXED_NOW), GroupSource(g)};
                        const int b{info.GetTriedBucket(nKey, EMPTY_NETGROUPMAN)};
                        per.insert(b);
                        tried_buckets.insert(b);
                    }
                    per_group_max = std::max(per_group_max, per.size());
                }
                BOOST_CHECK_LE(new_buckets.size(), static_cast<size_t>(F_linear(G, S)));
                BOOST_CHECK_LE(per_group_max, static_cast<size_t>(ADDRMAN_TRIED_BUCKETS_PER_GROUP));
                BOOST_CHECK_LE(tried_buckets.size(), static_cast<size_t>(T_linear(G)));

                csv.Row({I(k), I(G), I(H), I(S), I(new_buckets.size()), I(stage64.size()), D(F_linear(G, S), 1), D(F_bday1024(G, S), 2),
                         D(F_twostage(G, S), 2), I(tried_buckets.size()), I(per_group_max), D(T_linear(G), 1), D(T_bday256(G), 2)});
                auto& ag{agg[{G, H}]};
                ++ag.n;
                ag.s += new_buckets.size();
                ag.s2 += 1.0 * new_buckets.size() * new_buckets.size();
                ag.st += tried_buckets.size();
                ag.st2 += 1.0 * tried_buckets.size() * tried_buckets.size();
                ag.sp += stage64.size();
            }
        }
    }

    std::cout << strprintf("%3s %3s %3s | %9s %6s | %7s %7s %7s | %9s %6s | %6s %6s\n", "G", "H", "S", "new_mean", "sd", "F1lin", "F2bday", "F3two", "tried_mean", "sd", "T1lin", "T2bday");
    for (const auto& [gh, ag] : agg) {
        const auto [G, H] = gh;
        const double mean{ag.s / ag.n}, sd{std::sqrt(std::max(0.0, ag.s2 / ag.n - mean * mean))};
        const double tmean{ag.st / ag.n}, tsd{std::sqrt(std::max(0.0, ag.st2 / ag.n - tmean * tmean))};
        std::cout << strprintf("%3d %3d %3d | %9.2f %6.2f | %7.1f %7.2f %7.2f | %9.2f %6.2f | %6.1f %6.2f\n", G, H, G + H, mean, sd,
                               F_linear(G, G + H), F_bday1024(G, G + H), F_twostage(G, G + H), tmean, tsd, T_linear(G), T_bday256(G));
    }
}

// 2. Achievable share on synthetic honest backgrounds at several fill levels.
BOOST_AUTO_TEST_CASE(qmax_capacity_synthetic)
{
    FakeNodeClock clock{FIXED_NOW};
    const NodeSeconds now{Now<NodeSeconds>()};
    const int reps{EnvInt("QMAX_REPS", 2)};
    const int draws{EnvInt("QMAX_DRAWS", 50000)};
    const auto g_grid{EnvIntList("QMAX_G", {1, 2, 4, 8, 12, 16, 25})};
    const auto h_grid{EnvIntList("QMAX_H", {0, 10, 32, 64})};
    std::vector<std::string> fills{"sparse", "medium", "saturated"};
    if (const char* v{std::getenv("QMAX_FILLS")}) fills = SplitCsv(v);
    CsvWriter csv{OutDir() / "qmax_capacity_synthetic.csv", CAPACITY_HEADER};

    for (size_t fi{0}; fi < FILLS.size(); ++fi) {
        const auto& spec{FILLS[fi]};
        if (std::find(fills.begin(), fills.end(), spec.name) == fills.end()) continue;
        FastRandomContext bg_rng{CellRng("bg", 0, 0, fi, 0)};
        const DataStream bytes{BuildSyntheticBackground(spec, bg_rng, now)};
        std::set<Group16> forbidden;
        {
            auto am{FreshFromBytes(bytes, EMPTY_NETGROUPMAN)};
            forbidden = GroupsInAddrman(*am);
            const IsAttackerFn none{[](const CNetAddr&) { return false; }};
            const TableStats tn{MeasureTable(*am, false, none, now)};
            const TableStats tt{MeasureTable(*am, true, none, now)};
            std::cout << strprintf("background %-9s: new %5d slots in %4d buckets (honest displaceable %.3f: mult>1 %d, terrible %d), tried %5d slots in %3d buckets, %d /16s\n",
                                   spec.name, tn.slots_total, tn.n_nonempty, tn.honest_displaceable, tn.honest_mult_gt1, tn.honest_terrible,
                                   tt.slots_total, tt.n_nonempty, forbidden.size());
        }
        for (int rep{0}; rep < reps; ++rep) {
            for (const int G : g_grid) {
                for (const int H : h_grid) {
                    const bool validation{rep == 0 && ((spec.name == "sparse" && G == 1 && H == 0) ||
                                                       (spec.name == "medium" && G == 12 && H == 32) ||
                                                       (spec.name == "saturated" && G == 25 && H == 64))};
                    RunCapacityCell(csv, {"synthetic", spec.name, "fresh", rep, G, H, &bytes, &EMPTY_NETGROUPMAN, &forbidden, now,
                                          validation ? std::max(draws, 500000) : draws});
                }
            }
        }
    }
}

// 3. Same, on real peers.dat snapshots as background (no asmap, so the drawn
//    /16s are the netgroups), at the snapshot's own time and 31 days later
//    (everything honest is then terrible => pure hashing capacity).
BOOST_AUTO_TEST_CASE(qmax_capacity_snapshot)
{
    FakeNodeClock clock{FIXED_NOW};
    const int draws{EnvInt("QMAX_DRAWS", 50000)};
    const auto g_grid{EnvIntList("QMAX_G", {4, 12, 25})};
    const auto h_grid{EnvIntList("QMAX_H", {0, 32})};
    CsvWriter csv{OutDir() / "qmax_capacity_snapshot.csv", CAPACITY_HEADER};

    int found{0};
    for (const auto& snap : SNAPSHOTS) {
        const auto path{FindSnapshot(snap)};
        if (!path) continue;
        const auto bytes{LoadSnapshotBytes(*path)};
        BOOST_REQUIRE(bytes);
        ++found;
        NodeSeconds youngest;
        std::set<Group16> forbidden;
        {
            auto am{FreshFromBytes(*bytes, EMPTY_NETGROUPMAN)};
            youngest = YoungestNTime(*am);
            forbidden = GroupsInAddrman(*am);
            std::cout << strprintf("snapshot %s: %d new / %d tried addresses, %d /16s, youngest nTime %d\n", snap.name,
                                   am->Size(std::nullopt, true), am->Size(std::nullopt, false), forbidden.size(), TicksSinceEpoch<std::chrono::seconds>(youngest));
        }
        for (const std::string regime : {"youngest", "youngest+31d"}) {
            clock.set(regime == "youngest" ? youngest : youngest + 31 * 24h);
            const NodeSeconds now{Now<NodeSeconds>()};
            for (const int G : g_grid) {
                for (const int H : h_grid) {
                    RunCapacityCell(csv, {snap.name, "snapshot", regime, 0, G, H, &*bytes, &EMPTY_NETGROUPMAN, &forbidden, now, draws});
                }
            }
        }
    }
    if (found == 0) std::cout << "no snapshot files found; set QMAX_SNAPSHOT_DIR\n";
}

// 4. Tried half: move R reachable attacker addresses per group to tried via
//    Good(), exercising test-before-evict, and measure the tried share.
BOOST_AUTO_TEST_CASE(qmax_tried)
{
    FakeNodeClock clock{FIXED_NOW};
    const NodeSeconds now{Now<NodeSeconds>()};
    const int draws{EnvInt("QMAX_DRAWS", 50000)};
    const auto g_grid{EnvIntList("QMAX_G", {4, 12, 25})};
    const auto r_grid{EnvIntList("QMAX_R", {8, 64, 512})};
    const int H{EnvInt("QMAX_TRIED_H", 32)};
    std::vector<std::string> fills{"medium", "saturated"};
    if (const char* v{std::getenv("QMAX_FILLS")}) fills = SplitCsv(v);
    CsvWriter csv{OutDir() / "qmax_tried.csv",
                  "fill,G,H,R,goods_true,goods_false,att_tried_slots,tried_slots,tried_nonempty,B_att_tried,T1_linear,T2_bday256,own_frac_tried,"
                  "q_tried_mass,q_tried_chance,q_new_chance,q_new_pre_good,att_new_slots_pre,att_new_slots_post,q_full_exact,q_full_sampled,G_over_32,days_advanced,honest_tried_before,honest_tried_after"};

    for (size_t fi{0}; fi < FILLS.size(); ++fi) {
        const auto& spec{FILLS[fi]};
        if (std::find(fills.begin(), fills.end(), spec.name) == fills.end()) continue;
        clock.set(now); // the previous fill's cells advanced the clock; the build must see the same time as the capacity run
        FastRandomContext bg_rng{CellRng("bg", 0, 0, fi, 0)}; // same background as the synthetic capacity run
        const DataStream bytes{BuildSyntheticBackground(spec, bg_rng, now)};
        std::set<Group16> forbidden;
        {
            auto am{FreshFromBytes(bytes, EMPTY_NETGROUPMAN)};
            forbidden = GroupsInAddrman(*am);
        }
        for (const int G : g_grid) {
            for (const int R : r_grid) {
                clock.set(now);
                auto am{FreshFromBytes(bytes, EMPTY_NETGROUPMAN)};
                FastRandomContext rng{CellRng("tried/" + spec.name, G, H, R, 0)};
                const AttackerSpec aspec{DrawAttacker(rng, G, H, forbidden)};
                const IsAttackerFn is_att{[&aspec](const CNetAddr& a) { return aspec.Is(a); }};
                InjectAttackerNew(*am, aspec, now, ADDRS_PER_PAIR);
                const int honest_tried_before{static_cast<int>(am->Size(std::nullopt, false))};
                const TableStats tn_pre{MeasureTable(*am, false, is_att, now)};

                std::map<Group16, std::vector<CService>> by_group;
                for (const auto& [info, pos] : am->GetEntries(false)) {
                    if (!is_att(info)) continue;
                    auto& v{by_group[*Slash16Of(info)]};
                    if (static_cast<int>(v.size()) < R) v.push_back(info);
                }
                int goods_true{0}, goods_false{0}, calls{0};
                for (const auto& [g, addrs] : by_group) {
                    for (const auto& addr : addrs) {
                        if (am->Good(addr, Now<NodeSeconds>())) ++goods_true; else ++goods_false;
                        if (++calls % 10 == 0) {
                            clock += 41min;
                            am->ResolveCollisions();
                        }
                    }
                }
                clock += 41min;
                am->ResolveCollisions();
                clock += 11min; // clear the 10-minute GetChance penalty after Good()
                const NodeSeconds now2{Now<NodeSeconds>()};
                const double days{std::chrono::duration<double, std::ratio<86400>>(now2 - now).count()};

                const TableStats tn{MeasureTable(*am, false, is_att, now2)};
                const TableStats tt{MeasureTable(*am, true, is_att, now2)};
                const double q_full_s{SampleSelect(*am, false, is_att, draws)};
                const double q_full_exact{0.5 * (tn.q_chance + tt.q_chance)};
                const int honest_tried_after{tt.slots_total - tt.slots_att};

                BOOST_CHECK_LE(tt.b_att, static_cast<int>(T_linear(G)));
                BOOST_CHECK_LE(tt.slots_att, R * G);
                const double sd{std::sqrt(std::max(q_full_exact * (1 - q_full_exact), 1e-6) / draws)};
                BOOST_CHECK_MESSAGE(std::abs(q_full_s - q_full_exact) < 6 * sd + 0.002,
                                    strprintf("tried %s G=%d R=%d: sampled %.4f vs exact %.4f", spec.name, G, R, q_full_s, q_full_exact));

                csv.Row({spec.name, I(G), I(H), I(R), I(goods_true), I(goods_false), I(tt.slots_att), I(tt.slots_total), I(tt.n_nonempty), I(tt.b_att),
                         D(T_linear(G), 1), D(T_bday256(G), 2), D(tt.own_frac, 4), D(tt.q_mass), D(tt.q_chance), D(tn.q_chance), D(tn_pre.q_chance),
                         I(tn_pre.slots_att), I(tn.slots_att), D(q_full_exact), D(q_full_s), D(G / 32.0, 4), D(days, 2), I(honest_tried_before), I(honest_tried_after)});
                std::cout << strprintf("tried %-9s G=%2d R=%3d | Good true %5d false %5d | att tried slots %5d in %3d buckets (T2 %6.1f) | q_tried exact %.4f (G/32 = %.4f) | q_new pre %.4f post %.4f (att new slots %d -> %d) | q_full exact %.4f sampled %.4f | %.1f mock days\n",
                                       spec.name, G, R, goods_true, goods_false, tt.slots_att, tt.b_att, T_bday256(G), tt.q_chance, G / 32.0,
                                       tn_pre.q_chance, tn.q_chance, tn_pre.slots_att, tn.slots_att, q_full_exact, q_full_s, days);
            }
        }
    }
}

// 5. Real attacker in real snapshots: measured G, S (=> H), bucket reach and
//    exact draw share, next to the earlier harness' q raw / q measured.
BOOST_AUTO_TEST_CASE(qmax_snapshot_crosscheck)
{
    FakeNodeClock clock{FIXED_NOW};
    CsvWriter csv{OutDir() / "qmax_snapshot_crosscheck.csv",
                  "name,asmap,new_slots,tried_slots,exp_new,exp_tried,bp_new_slots,bp_tried_slots,exp_bp_new,exp_bp_tried,G_att,S_att,H_att,"
                  "new_nonempty,tried_nonempty,B_att_new,own_frac_new,B_att_tried,F1_linear,F2_bday1024,F3_twostage,T1_linear,T2_bday256,"
                  "q_raw,q_exact_mass,q_exact_chance,q_prompt,q_prompt_bday,q_corrected,q_raw_prev,q_measured_prev"};

    int found{0};
    for (const auto& snap : SNAPSHOTS) {
        const auto path{FindSnapshot(snap)};
        if (!path) continue;
        const auto bytes{LoadSnapshotBytes(*path)};
        BOOST_REQUIRE(bytes);
        ++found;
        const NetGroupManager ngm{snap.asmap ? NetGroupManager::WithEmbeddedAsmap(node::data::ip_asn) : NetGroupManager::NoAsmap()};
        auto am{FreshFromBytes(*bytes, ngm)};
        const NodeSeconds youngest{YoungestNTime(*am)};
        clock.set(youngest);
        const NodeSeconds now{Now<NodeSeconds>()};

        std::set<std::vector<unsigned char>> att_groups, att_sources;
        for (const bool tried : {false, true}) {
            for (const auto& [info, pos] : am->GetEntries(tried)) {
                if (!IsBitprojects(info)) continue;
                att_groups.insert(ngm.GetGroup(info));
                att_sources.insert(ngm.GetGroup(info.source));
            }
        }
        const int G_att{static_cast<int>(att_groups.size())};
        const int S_att{static_cast<int>(att_sources.size())};
        const TableStats tn{MeasureTable(*am, false, IsBitprojects, now)};
        const TableStats tt{MeasureTable(*am, true, IsBitprojects, now)};
        const double q_raw{0.5 * (tn.slots_total ? 1.0 * tn.slots_att / tn.slots_total : 0) + 0.5 * (tt.slots_total ? 1.0 * tt.slots_att / tt.slots_total : 0)};
        const double q_exact_mass{0.5 * (tn.q_mass + tt.q_mass)};
        const double q_exact_chance{0.5 * (tn.q_chance + tt.q_chance)};
        const double q_corrected{0.5 * (tn.n_nonempty ? 1.0 * tn.b_att / tn.n_nonempty * tn.own_frac : 0) + 0.5 * (tt.n_nonempty ? 1.0 * tt.b_att / tt.n_nonempty * tt.own_frac : 0)};
        const auto [q_raw_prev, q_measured_prev] = ParseResultsTxt(snap.name);

        if (snap.exp_new >= 0) {
            BOOST_WARN_EQUAL(tn.slots_total, snap.exp_new);
            BOOST_WARN_EQUAL(tt.slots_total, snap.exp_tried);
            BOOST_WARN_EQUAL(tn.slots_att, snap.exp_bp_new);
            BOOST_WARN_EQUAL(tt.slots_att, snap.exp_bp_tried);
        }
        csv.Row({snap.name, I(snap.asmap), I(tn.slots_total), I(tt.slots_total), I(snap.exp_new), I(snap.exp_tried), I(tn.slots_att), I(tt.slots_att),
                 I(snap.exp_bp_new), I(snap.exp_bp_tried), I(G_att), I(S_att), I(S_att - G_att), I(tn.n_nonempty), I(tt.n_nonempty), I(tn.b_att),
                 D(tn.own_frac, 4), I(tt.b_att), D(F_linear(G_att, S_att), 1), D(F_bday1024(G_att, S_att), 2), D(F_twostage(G_att, S_att), 2),
                 D(T_linear(G_att), 1), D(T_bday256(G_att), 2), D(q_raw), D(q_exact_mass), D(q_exact_chance), D(Q_prompt(G_att, S_att)),
                 D(Q_prompt_bday(G_att, S_att)), D(q_corrected), D(q_raw_prev), D(q_measured_prev)});
        std::cout << strprintf("%s (asmap %d): new %d/%d (exp %d) tried %d/%d (exp %d) | G_att %d S_att %d (H %d) | B_att new %d (F1 %.0f F3 %.1f) tried %d (T2 %.1f) | q raw %.4f exact mass %.4f chance %.4f | prev raw %.4f measured %.4f | q_prompt %.4f\n",
                               snap.name, snap.asmap, tn.slots_att, tn.slots_total, snap.exp_new, tt.slots_att, tt.slots_total, snap.exp_tried, G_att, S_att,
                               S_att - G_att, tn.b_att, F_linear(G_att, S_att), F_twostage(G_att, S_att), tt.b_att, T_bday256(G_att), q_raw, q_exact_mass,
                               q_exact_chance, q_raw_prev, q_measured_prev, Q_prompt(G_att, S_att));
    }
    if (found == 0) std::cout << "no snapshot files found; set QMAX_SNAPSHOT_DIR\n";
}

BOOST_AUTO_TEST_SUITE_END()
