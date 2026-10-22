#include "state.h"

#include <iomanip>
#include <iostream>
#include <utility>

#include "crypto/aes.h"

namespace {

constexpr uint8_t kScrambleEven = 0x02;
constexpr uint8_t kScrambleOdd = 0x03;

void put_be16(uint8_t *p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value >> 8);
    p[1] = static_cast<uint8_t>(value);
}

void put_be32(uint8_t *p, uint32_t value)
{
    p[0] = static_cast<uint8_t>(value >> 24);
    p[1] = static_cast<uint8_t>(value >> 16);
    p[2] = static_cast<uint8_t>(value >> 8);
    p[3] = static_cast<uint8_t>(value);
}

} // namespace

AcasState::AcasState(std::unique_ptr<AcasCardClient> card)
    : card(std::move(card))
{
}

void AcasState::set_proxy(const std::string& address)
{
    card->set_proxy(address);
}

bool AcasState::on_ecm(const std::vector<uint8_t>& ecm,
                       const acas_ecm_metadata& metadata)
{
    if (ecm == last_ecm && has_key) {
        return true;
    }

    /*
     * A new ECM supersedes the old key generation. Do not let a failed card
     * transaction fall through to decryption with the previous keys; leave
     * packets scrambled and retry when the repeated ECM arrives.
     */
    has_key = false;
    acas_ecm_result result;
    if (!card->process_ecm(ecm, result)) {
        log_ecm("rejected", metadata, result.return_code, result.broadcaster_id);
        return false;
    }

    odd_key = result.odd_key;
    even_key = result.even_key;
    last_ecm = ecm;
    has_key = true;
    log_ecm("updated", metadata, result.return_code, result.broadcaster_id);
    return true;
}

void AcasState::on_emm_section(const uint8_t *data, size_t size)
{
    acas_card_identity identity;
    if (!card->get_identity(identity)) {
        std::cerr << "ACAS EMM ignored: cannot read CAS module identity" << std::endl;
        return;
    }

    std::vector<uint8_t> emm;
    if (!acas_select_emm_payload(data, size, identity.module_id, emm) ||
        emm == last_emm) {
        return;
    }

    uint16_t return_code = 0;
    if (!card->process_emm(emm, return_code)) {
        std::cerr << "ACAS EMM rejected: return=0x" << std::hex
                  << std::setw(4) << std::setfill('0') << return_code
                  << std::setfill(' ') << std::dec << std::endl;
        return;
    }

    last_emm = std::move(emm);
    last_ecm.clear();
    std::cerr << "ACAS EMM updated work-key state: ca_system_id=0x"
              << std::hex << std::setw(4) << std::setfill('0')
              << identity.ca_system_id << std::setfill(' ') << std::dec
              << std::endl;
}

bool AcasState::decrypt_payload(uint8_t scramble_flag,
                                uint16_t packet_id,
                                uint32_t packet_sequence_number,
                                uint8_t *payload,
                                size_t payload_size,
                                size_t decrypt_size,
                                const std::array<uint8_t, 16> *initial_counter)
{
    if (payload_size < decrypt_size || decrypt_size <= 8 || !has_key) {
        return false;
    }

    const std::array<uint8_t, 16> *key = nullptr;
    if (scramble_flag == kScrambleEven) {
        key = &even_key;
    } else if (scramble_flag == kScrambleOdd) {
        key = &odd_key;
    }
    if (!key) {
        return false;
    }

    std::array<uint8_t, 16> iv{};
    if (initial_counter) {
        iv = *initial_counter;
    } else {
        put_be16(iv.data(), packet_id);
        put_be32(iv.data() + 2, packet_sequence_number);
    }

    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key->data(), iv.data());
    AES_CTR_xcrypt_buffer(&ctx, payload + 8, decrypt_size - 8);
    return true;
}

void AcasState::log_ecm(const char *state,
                        const acas_ecm_metadata& metadata,
                        uint16_t return_code,
                        uint8_t broadcaster_id)
{
    std::cerr << "ACAS ECM " << state
              << ": format=" << (metadata.is_f1 ? "F1" : "F0")
              << " group=0x" << std::hex << std::setw(4)
              << std::setfill('0') << metadata.broadcaster_group_id
              << " work_key_id=0x" << std::setw(2)
              << static_cast<unsigned>(metadata.work_key_id);
    if (metadata.is_f1) {
        std::cerr << " pairs=" << std::dec
                  << static_cast<unsigned>(metadata.scrambling_key_pair_count);
    }
    std::cerr << " return=0x" << std::hex << std::setw(4) << return_code
              << " card_broadcaster=0x" << std::setw(2)
              << static_cast<unsigned>(broadcaster_id)
              << std::setfill(' ') << std::dec << std::endl;
}
