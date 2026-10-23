#ifndef ACAS_STATE_H
#define ACAS_STATE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "card.h"
#include "routing.h"
#include "sections.h"

class AcasState {
public:
    explicit AcasState(std::unique_ptr<AcasCardClient> card = make_acas_card_client());

    void set_verbose(bool enabled) { verbose = enabled; }
    void set_proxy(const std::string& address);
    bool get_ca_system_id(uint16_t& id);
    std::optional<uint16_t> ca_system_id() const {
        return identity ? std::optional<uint16_t>(identity->ca_system_id) : std::nullopt;
    }
    void retain_ecm_streams(const std::set<uint32_t>& streams);
    void invalidate_ecm_stream(uint32_t stream) { keys.erase(stream); }
    bool on_ecm(uint32_t stream_id, const std::vector<uint8_t>& ecm, const acas_ecm_metadata& metadata);
    void on_emm_section(const uint8_t *data, size_t size);
    bool decrypt_payload(uint32_t ecm_stream_id, ScramblingAlgorithm algorithm,
                         uint8_t scramble_flag,
                         uint16_t packet_id,
                         uint32_t packet_sequence_number,
                         uint8_t *payload,
                         size_t payload_size,
                         size_t decrypt_size,
                         const std::array<uint8_t, 16> *initial_counter);

private:
    static void log_ecm(const char *state,
                        const acas_ecm_metadata& metadata,
                        uint16_t return_code,
                        uint8_t broadcaster_id);

    std::unique_ptr<AcasCardClient> card;
    std::optional<acas_card_identity> identity;
    std::set<std::vector<uint8_t>> processed_emms;
    struct KeyState {
        std::vector<uint8_t> last_ecm;
        std::array<uint8_t, 16> odd_key{}, even_key{};
        bool has_key = false;
        std::string last_failure;
    };
    std::map<uint32_t, KeyState> keys;
    bool verbose = false;
    bool emm_identity_failed = false;
};

#endif
