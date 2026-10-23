#include "state.h"
#include <cstdlib>
#include <iostream>

void check(bool ok) { if (!ok) { std::cerr << "retry invariant failed\n"; std::exit(1); } }
struct Card : AcasCardClient {
    AcasState::Clock::time_point& time;
    int calls = 0;
    bool success = false;
    bool rejection = false;
    explicit Card(AcasState::Clock::time_point& t) : time(t) {}
    void set_proxy(const std::string&) override {}
    bool get_identity(acas_card_identity& id) override { id.ca_system_id = 1; return true; }
    bool process_emm(const std::vector<uint8_t>&, uint16_t&) override { return true; }
    bool process_ecm(const std::vector<uint8_t>&, acas_ecm_result& result) override {
        ++calls;
        time += std::chrono::milliseconds(150);
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
}
