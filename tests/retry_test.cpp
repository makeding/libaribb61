#include "state.h"
#include "stream_test_support.h"
#include <cstdlib>
#include <iostream>

void check(bool ok) { if (!ok) { std::cerr << "retry invariant failed\n"; std::exit(1); } }
struct Card : AcasCardClient {
    AcasState::Clock::time_point& time;
    int calls = 0;
    int latency_ms = 150;
    uint8_t module = 0;
    bool success = false;
    bool rejection = false;
    explicit Card(AcasState::Clock::time_point& t) : time(t) {}
    void set_proxy(const std::string&) override {}
    bool get_identity(acas_card_identity& id) override { id.ca_system_id = 1; id.module_id[0] = module; return true; }
    bool process_emm(const std::vector<uint8_t>&, uint16_t&) override { return true; }
    bool process_ecm(const std::vector<uint8_t>&, acas_ecm_result& result) override {
        ++calls;
        time += std::chrono::milliseconds(latency_ms);
        result.response_valid = rejection || success;
        return success;
    }
};
int main() {
    AcasState::Clock::time_point time{};
    auto card = std::make_unique<Card>(time);
    auto* fake = card.get();
    AcasState state(std::move(card), [&] { return time; });
    acas_ecm_metadata metadata{};
    uint16_t ca_system;
    check(state.get_ca_system_id(ca_system));
    check(!state.on_ecm(1, {1}, metadata) && fake->calls == 1);
    time += std::chrono::milliseconds(100);
    check(!state.on_ecm(1, {1}, metadata) && fake->calls == 1);
    time += std::chrono::milliseconds(150);
    fake->success = true;
    check(state.on_ecm(1, {1}, metadata) && fake->calls == 2);
    check(state.on_ecm(1, {1}, metadata) && fake->calls == 2);
    fake->success = false;
    check(!state.on_ecm(1, {2}, metadata) && fake->calls == 3);
    uint8_t payload[16]{};
    check(!state.decrypt_payload(1, ScramblingAlgorithm::Aes128Ctr, 2, 1, 1,
                                 payload, 16, 16, nullptr));
    check(!state.on_ecm(1, {3}, metadata) && fake->calls == 4);
    check(!state.on_ecm(2, {3}, metadata) && fake->calls == 5);
    state.invalidate_ecm_stream(1);
    check(!state.on_ecm(1, {3}, metadata) && fake->calls == 6);
    fake->rejection = true;
    check(!state.on_ecm(1, {4}, metadata) && fake->calls == 7);
    check(!state.on_ecm(1, {4}, metadata) && fake->calls == 8);
    fake->rejection = false;
    fake->latency_ms = 1;
    check(!state.on_ecm(1, {5}, metadata) && fake->calls == 9);
    check(!state.on_ecm(1, {5}, metadata) && fake->calls == 10);
    fake->latency_ms = 150;
    check(!state.on_ecm(1, {6}, metadata) && fake->calls == 11);
    const auto emm = aribb61_test::make_section(0x84,
        {0, 0, 0, 0, 0, 0, 4, 0x20, 0x42, 1, 0xaa});
    state.on_emm_section(emm.data(), emm.size());
    check(!state.on_ecm(1, {6}, metadata) && fake->calls == 12);
    fake->module = 1;
    check(state.get_ca_system_id(ca_system));
    check(!state.on_ecm(1, {6}, metadata) && fake->calls == 13);
}
