#ifndef ACAS_RESPONSE_H
#define ACAS_RESPONSE_H

#include <array>
#include <cstdint>
#include <vector>

struct acas_ecm_card_response {
    uint16_t return_code = 0;
    uint8_t broadcaster_id = 0;
    std::array<uint8_t, 32> encrypted_keys{};
};

bool acas_parse_ecm_card_response(const std::vector<uint8_t>& response,
                                  acas_ecm_card_response& parsed);

#endif
