#ifndef ACAS_SECTIONS_H
#define ACAS_SECTIONS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

struct acas_ecm_metadata {
    uint8_t protocol_number = 0;
    uint16_t broadcaster_group_id = 0;
    uint8_t work_key_id = 0;
    bool is_f1 = false;
    uint8_t scrambling_key_pair_count = 0;
};

bool acas_parse_ecm_section(const uint8_t *data,
                            size_t size,
                            std::vector<uint8_t>& ecm,
                            acas_ecm_metadata& metadata);

bool acas_select_emm_payload(const uint8_t *data,
                             size_t size,
                             const std::array<uint8_t, 6>& cas_module_id,
                             std::vector<uint8_t>& emm);

#endif
