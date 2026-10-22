#ifndef ACAS_CARD_H
#define ACAS_CARD_H

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct acas_card_identity {
    uint16_t ca_system_id = 0;
    std::array<uint8_t, 6> module_id{};
};

struct acas_ecm_result {
    std::array<uint8_t, 16> odd_key{};
    std::array<uint8_t, 16> even_key{};
    uint16_t return_code = 0;
    uint8_t broadcaster_id = 0;
};

class AcasCardClient {
public:
    virtual ~AcasCardClient() = default;
    virtual void set_proxy(const std::string& address) = 0;
    virtual bool get_identity(acas_card_identity& identity) = 0;
    virtual bool process_ecm(const std::vector<uint8_t>& ecm, acas_ecm_result& result) = 0;
    virtual bool process_emm(const std::vector<uint8_t>& emm, uint16_t& return_code) = 0;
};

std::unique_ptr<AcasCardClient> make_acas_card_client();

#endif
