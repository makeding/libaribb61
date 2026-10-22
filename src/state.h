#ifndef ACAS_STATE_H
#define ACAS_STATE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "card.h"
#include "sections.h"

class AcasState {
public:
    explicit AcasState(std::unique_ptr<AcasCardClient> card = make_acas_card_client());

    void set_proxy(const std::string& address);
    bool on_ecm(const std::vector<uint8_t>& ecm, const acas_ecm_metadata& metadata);
    void on_emm_section(const uint8_t *data, size_t size);
    bool decrypt_payload(uint8_t scramble_flag,
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
    std::vector<uint8_t> last_ecm;
    std::vector<uint8_t> last_emm;
    std::array<uint8_t, 16> odd_key{};
    std::array<uint8_t, 16> even_key{};
    bool has_key = false;
};

#endif
