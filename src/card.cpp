#include "card.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#include <utility>

#include "config.h"

#if defined(HAVE_PCSC_WINSCARD_H) || defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

#include "crypto/sha256.h"
#include "proxy/client.h"
#include "response.h"

namespace {

constexpr uint8_t kMasterKey[] = {
    0x4F, 0x4C, 0x7C, 0xEB, 0x34, 0xFE, 0xB0, 0xA3,
    0x1E, 0x41, 0x19, 0x51, 0xE1, 0x35, 0x15, 0x12,
    0x87, 0xD3, 0x3D, 0x33, 0xD4, 0x9B, 0x4F, 0x52,
    0x05, 0x77, 0xF9, 0xEF, 0xE5, 0x56, 0x1F, 0x32,
};

uint16_t be16(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

std::vector<uint8_t> apdu_case2(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t le)
{
    return { cla, ins, p1, p2, le };
}

std::vector<uint8_t> apdu_case4(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                                const std::vector<uint8_t>& data, uint8_t le)
{
    if (data.size() > 0xff) {
        throw std::runtime_error("ACAS APDU payload is too large");
    }
    std::vector<uint8_t> apdu = { cla, ins, p1, p2, static_cast<uint8_t>(data.size()) };
    apdu.insert(apdu.end(), data.begin(), data.end());
    apdu.push_back(le);
    return apdu;
}

bool has_success_status(const std::vector<uint8_t>& response)
{
    return response.size() >= 2 && response[response.size() - 2] == 0x90 &&
           response[response.size() - 1] == 0x00;
}

class PcscCard {
public:
    ~PcscCard()
    {
        try {
            if (hcard) {
                scard_disconnect(hcard, SCARD_LEAVE_CARD);
            }
            if (hcontext) {
                scard_release_context(hcontext);
            }
        } catch (const std::exception&) {
            // Destruction must not terminate a recording process after a proxy disconnect.
        }
    }

    void set_proxy(const std::string& address)
    {
        if (hcontext || hcard) {
            throw std::runtime_error("Cannot change CAS proxy after opening a smart card");
        }
        auto parsed = casproxy::parseAddress(address);
        if (!parsed) {
            throw std::runtime_error("Invalid CAS proxy address: " + address);
        }
        proxy = std::make_unique<CasProxyClient>(parsed->first, parsed->second);
    }

    int32_t reconnect()
    {
        if (!hcard) {
            connect();
            return SCARD_S_SUCCESS;
        }
        return scard_reconnect(hcard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
                               SCARD_RESET_CARD, &active_protocol);
    }

    std::vector<uint8_t> transmit(const std::vector<uint8_t>& message, int32_t *status)
    {
        connect();

        DWORD recv_length = 256;
        std::vector<uint8_t> recv(recv_length);
        int32_t result = scard_transmit(hcard, SCARD_PCI_T1, message.data(),
                                       static_cast<uint32_t>(message.size()),
                                       nullptr, recv.data(), &recv_length);
        for (int retry = 0; result != SCARD_S_SUCCESS && retry < 5; ++retry) {
            if (result == SCARD_W_RESET_CARD || result == SCARD_E_NOT_TRANSACTED) {
                *status = SCARD_W_RESET_CARD;
                return {};
            }
            recv_length = 256;
            result = scard_transmit(hcard, SCARD_PCI_T1, message.data(),
                                    static_cast<uint32_t>(message.size()),
                                    nullptr, recv.data(), &recv_length);
        }
        *status = result;
        if (result != SCARD_S_SUCCESS || recv_length < 2) {
            return {};
        }

        recv.resize(recv_length);
        return recv;
    }

    void begin()
    {
        connect();
        const LONG result = scard_begin_transaction(hcard);
        if (result != SCARD_S_SUCCESS) {
            throw std::runtime_error("SCardBeginTransaction failed: " + std::to_string(result));
        }
    }

    void end()
    {
        if (hcard) {
            scard_end_transaction(hcard, SCARD_LEAVE_CARD);
        }
    }

private:
    LONG scard_establish_context(DWORD scope, LPSCARDCONTEXT context)
    {
        return proxy ? proxy->scardEstablishContext(scope, nullptr, nullptr, context)
                     : SCardEstablishContext(scope, nullptr, nullptr, context);
    }

    LONG scard_release_context(SCARDCONTEXT context)
    {
        return proxy ? proxy->scardReleaseContext(context) : SCardReleaseContext(context);
    }

    LONG scard_list_readers(SCARDCONTEXT context, LPSTR readers, LPDWORD size)
    {
        return proxy ? proxy->scardListReaders(context, nullptr, readers, size)
                     : SCardListReaders(context, nullptr, readers, size);
    }

    LONG scard_connect(SCARDCONTEXT context, LPCSTR reader, LPSCARDHANDLE card,
                       LPDWORD protocol)
    {
        return proxy ? proxy->scardConnect(context, reader, SCARD_SHARE_SHARED,
                                           SCARD_PROTOCOL_T1, card, protocol)
                     : SCardConnect(context, reader, SCARD_SHARE_SHARED,
                                    SCARD_PROTOCOL_T1, card, protocol);
    }

    LONG scard_reconnect(SCARDHANDLE card, DWORD share_mode, DWORD protocols,
                         DWORD initialization, LPDWORD active_protocol)
    {
        return proxy ? proxy->scardReconnect(card, share_mode, protocols,
                                             initialization, active_protocol)
                     : SCardReconnect(card, share_mode, protocols,
                                      initialization, active_protocol);
    }

    LONG scard_disconnect(SCARDHANDLE card, DWORD disposition)
    {
        return proxy ? proxy->scardDisconnect(card, disposition)
                     : SCardDisconnect(card, disposition);
    }

    LONG scard_begin_transaction(SCARDHANDLE card)
    {
        return proxy ? proxy->scardBeginTransaction(card) : SCardBeginTransaction(card);
    }

    LONG scard_end_transaction(SCARDHANDLE card, DWORD disposition)
    {
        return proxy ? proxy->scardEndTransaction(card, disposition)
                     : SCardEndTransaction(card, disposition);
    }

    LONG scard_transmit(SCARDHANDLE card, LPCSCARD_IO_REQUEST send_pci,
                        LPCBYTE send_buffer, DWORD send_length,
                        LPSCARD_IO_REQUEST recv_pci, LPBYTE recv_buffer,
                        LPDWORD recv_length)
    {
        return proxy ? proxy->scardTransmit(card, send_pci, send_buffer, send_length,
                                            recv_pci, recv_buffer, recv_length)
                     : SCardTransmit(card, send_pci, send_buffer, send_length,
                                     recv_pci, recv_buffer, recv_length);
    }

    void init()
    {
        if (hcontext) {
            return;
        }
        int32_t result = scard_establish_context(SCARD_SCOPE_USER, &hcontext);
        if (result != SCARD_S_SUCCESS) {
            throw std::runtime_error("SCardEstablishContext failed");
        }
    }

    bool is_acas_card(SCARDHANDLE card)
    {
        std::default_random_engine engine(std::random_device{}());
        std::uniform_int_distribution<int> distrib(0, 255);

        std::vector<uint8_t> data = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x8A, 0xF7 };
        std::vector<uint8_t> a0init(8);
        for (uint8_t& v : a0init) {
            v = static_cast<uint8_t>(distrib(engine));
        }
        data.insert(data.end(), a0init.begin(), a0init.end());

        std::vector<uint8_t> apdu = apdu_case4(0x90, 0xA0, 0x00, 0x01, data, 0x00);
        DWORD recv_length = 256;
        std::vector<uint8_t> recv(recv_length);
        LONG result = scard_transmit(card, SCARD_PCI_T1, apdu.data(),
                                     static_cast<DWORD>(apdu.size()),
                                     nullptr, recv.data(), &recv_length);
        if (result != SCARD_S_SUCCESS || recv_length < 0x0e + 0x20 + 2) {
            return false;
        }
        recv.resize(recv_length);
        if (!has_success_status(recv)) {
            return false;
        }

        std::vector<uint8_t> a0data(recv.begin(), recv.end() - 2);
        std::vector<uint8_t> a0response(a0data.begin() + 0x06, a0data.begin() + 0x0e);
        std::vector<uint8_t> a0hash(a0data.begin() + 0x0e, a0data.begin() + 0x0e + 0x20);

        std::vector<uint8_t> plain_kcl;
        plain_kcl.insert(plain_kcl.end(), std::begin(kMasterKey), std::end(kMasterKey));
        plain_kcl.insert(plain_kcl.end(), a0init.begin(), a0init.end());
        plain_kcl.insert(plain_kcl.end(), a0response.begin(), a0response.end());
        sha256_t kcl = SHA256::hash(plain_kcl);

        std::vector<uint8_t> plain_data;
        plain_data.insert(plain_data.end(), kcl.begin(), kcl.end());
        plain_data.insert(plain_data.end(), a0init.begin(), a0init.end());
        sha256_t hash = SHA256::hash(plain_data);

        return std::equal(hash.begin(), hash.end(), a0hash.begin());
    }

    std::string find_acas_reader()
    {
        init();
        DWORD size = 0;
        int32_t result = scard_list_readers(hcontext, nullptr, &size);
        if (result != SCARD_S_SUCCESS || size == 0) {
            throw std::runtime_error("No smart card readers are available");
        }

        std::vector<char> readers(size);
        result = scard_list_readers(hcontext, readers.data(), &size);
        if (result != SCARD_S_SUCCESS || readers.empty() || readers[0] == '\0') {
            throw std::runtime_error("Failed to list smart card readers");
        }

        if (proxy) {
            return std::string(readers.data());
        }

        for (const char *reader = readers.data(); *reader; reader += std::strlen(reader) + 1) {
            SCARDHANDLE candidate = 0;
            DWORD active_protocol = 0;
            result = scard_connect(hcontext, reader, &candidate, &active_protocol);
            if (result != SCARD_S_SUCCESS) {
                continue;
            }

            bool matched = is_acas_card(candidate);
            scard_disconnect(candidate, SCARD_LEAVE_CARD);
            if (matched) {
                return std::string(reader);
            }
        }

        throw std::runtime_error("No ACAS smart card was found");
    }

    void connect()
    {
        init();
        if (hcard) {
            return;
        }
        reader_name = find_acas_reader();
        int32_t result = scard_connect(hcontext, reader_name.c_str(), &hcard,
                                      &active_protocol);
        if (result != SCARD_S_SUCCESS) {
            throw std::runtime_error("Failed to connect to smart card: " + reader_name);
        }
    }

    std::unique_ptr<CasProxyClient> proxy;
    SCARDCONTEXT hcontext = 0;
    SCARDHANDLE hcard = 0;
    DWORD active_protocol = 0;
    std::string reader_name;
};

class Transaction {
public:
    explicit Transaction(PcscCard& card) : card(card) { card.begin(); }
    ~Transaction()
    {
        try {
            card.end();
        } catch (const std::exception& e) {
            std::cerr << e.what() << std::endl;
        }
    }

private:
    PcscCard& card;
};

class PcscAcasCardClient final : public AcasCardClient {
public:
    void set_proxy(const std::string& address) override
    {
        card.set_proxy(address);
    }

    bool get_identity(acas_card_identity& output) override
    {
        if (identity_valid) {
            output = identity;
            return true;
        }

        for (int retry = 0; retry < 5; ++retry) {
            try {
                Transaction transaction(card);
                int32_t status = SCARD_S_SUCCESS;
                auto response = card.transmit(apdu_case2(0x90, 0x30, 0x00, 0x01, 0x00), &status);
                if (status == SCARD_W_RESET_CARD) {
                    card.reconnect();
                    continue;
                }
                if (status != SCARD_S_SUCCESS || response.size() < 17 + 2 ||
                    !has_success_status(response) || be16(response.data() + 4) != 0x2100) {
                    return false;
                }
                const size_t system_id_count = response[16];
                if (response.size() < 17 + system_id_count * 2 + 2) {
                    return false;
                }
                identity.ca_system_id = be16(response.data() + 6);
                std::copy(response.begin() + 8, response.begin() + 14, identity.module_id.begin());
                identity_valid = true;
                output = identity;
                return true;
            } catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
                return false;
            }
        }
        return false;
    }

    bool process_ecm(const std::vector<uint8_t>& ecm, acas_ecm_result& output) override
    {
        acas_card_identity unused;
        if (ecm.size() < 0x1b || !get_identity(unused)) {
            return false;
        }

        for (int retry = 0; retry < 5; ++retry) {
            try {
                Transaction transaction(card);
                sha256_t kcl;
                if (!get_a0_auth_kcl(kcl)) {
                    return false;
                }

                int32_t status = SCARD_S_SUCCESS;
                auto response = card.transmit(apdu_case4(0x90, 0x34, 0x00, 0x01, ecm, 0x00), &status);
                if (status == SCARD_W_RESET_CARD) {
                    identity_valid = false;
                    card.reconnect();
                    continue;
                }
                if (status != SCARD_S_SUCCESS) {
                    return false;
                }

                acas_ecm_card_response parsed;
                const bool viewable = acas_parse_ecm_card_response(response, parsed);
                output.return_code = parsed.return_code;
                output.broadcaster_id = parsed.broadcaster_id;
                if (!viewable) {
                    return false;
                }

                std::vector<uint8_t> ecm_init(ecm.begin() + 0x04, ecm.begin() + 0x04 + 0x17);
                std::vector<uint8_t> plain_data(kcl.begin(), kcl.end());
                plain_data.insert(plain_data.end(), ecm_init.begin(), ecm_init.end());
                sha256_t keys = SHA256::hash(plain_data);
                for (size_t i = 0; i < keys.size(); ++i) {
                    keys[i] ^= parsed.encrypted_keys[i];
                }
                std::copy(keys.begin(), keys.begin() + 0x10, output.odd_key.begin());
                std::copy(keys.begin() + 0x10, keys.end(), output.even_key.begin());
                return true;
            } catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
                return false;
            }
        }
        return false;
    }

    bool process_emm(const std::vector<uint8_t>& emm, uint16_t& return_code) override
    {
        for (int retry = 0; retry < 5; ++retry) {
            try {
                Transaction transaction(card);
                int32_t status = SCARD_S_SUCCESS;
                auto response = card.transmit(apdu_case4(0x90, 0x36, 0x00, 0x01, emm, 0x00), &status);
                if (status == SCARD_W_RESET_CARD) {
                    identity_valid = false;
                    card.reconnect();
                    continue;
                }
                if (status != SCARD_S_SUCCESS || response.size() < 6 + 2 ||
                    !has_success_status(response)) {
                    return false;
                }
                return_code = be16(response.data() + 4);
                return return_code == 0x2100;
            } catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
                return false;
            }
        }
        return false;
    }

private:
    bool get_a0_auth_kcl(sha256_t& output)
    {
        std::default_random_engine engine(std::random_device{}());
        std::uniform_int_distribution<int> distrib(0, 255);

        std::vector<uint8_t> data = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x8A, 0xF7 };
        std::vector<uint8_t> a0init(8);
        for (uint8_t& b : a0init) {
            b = static_cast<uint8_t>(distrib(engine));
        }
        data.insert(data.end(), a0init.begin(), a0init.end());

        int32_t status = SCARD_S_SUCCESS;
        auto response = card.transmit(apdu_case4(0x90, 0xA0, 0x00, 0x01, data, 0x00), &status);
        if (status != SCARD_S_SUCCESS || response.size() < 0x0e + 32 + 2 ||
            !has_success_status(response)) {
            return false;
        }

        std::vector<uint8_t> a0data(response.begin(), response.end() - 2);
        std::vector<uint8_t> a0response(a0data.begin() + 0x06, a0data.begin() + 0x0e);
        std::vector<uint8_t> a0hash(a0data.begin() + 0x0e, a0data.end());

        std::vector<uint8_t> plain_kcl(std::begin(kMasterKey), std::end(kMasterKey));
        plain_kcl.insert(plain_kcl.end(), a0init.begin(), a0init.end());
        plain_kcl.insert(plain_kcl.end(), a0response.begin(), a0response.end());
        sha256_t kcl = SHA256::hash(plain_kcl);

        std::vector<uint8_t> plain_data(kcl.begin(), kcl.end());
        plain_data.insert(plain_data.end(), a0init.begin(), a0init.end());
        sha256_t hash = SHA256::hash(plain_data);
        if (a0hash.size() < hash.size() || !std::equal(hash.begin(), hash.end(), a0hash.begin())) {
            return false;
        }

        output = kcl;
        return true;
    }

    PcscCard card;
    acas_card_identity identity;
    bool identity_valid = false;
};

} // namespace

std::unique_ptr<AcasCardClient> make_acas_card_client()
{
    return std::make_unique<PcscAcasCardClient>();
}
