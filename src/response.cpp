#include "response.h"

#include <algorithm>

namespace {

uint16_t be16(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

bool is_viewable(uint16_t return_code)
{
    return return_code == 0x0800 || return_code == 0x0600 || return_code == 0x4680;
}

} // namespace

bool acas_parse_ecm_card_response(const std::vector<uint8_t>& response,
                                  acas_ecm_card_response& parsed)
{
    if (response.size() < 6 + parsed.encrypted_keys.size() + 1 + 2) {
        return false;
    }

    parsed.return_code = be16(response.data() + 4);
    parsed.broadcaster_id = response[38];
    if (response[response.size() - 2] != 0x90 || response.back() != 0x00) {
        return false;
    }

    std::copy(response.begin() + 6, response.begin() + 38,
              parsed.encrypted_keys.begin());
    return is_viewable(parsed.return_code);
}
