/*
 * Derived from dantto4k ACAS/MMT-TLV code.
 *
 * Original project: https://github.com/nekohkr/dantto4k.git
 * Local source revision: 141fd49cf674c9c9e3f3c770a20b3291ff292969
 * Original source areas:
 *   - src/acasCard.{h,cpp}
 *   - src/smartCard.{h,cpp}
 *   - src/acasHandler.{h,cpp}
 *   - src/mmtTlvDemuxer.cpp
 *   - src/signalingMessage.{h,cpp}
 *   - src/fragmentAssembler.{h,cpp}
 *   - src/mmtp.{h,cpp}
 *   - src/tlv.{h,cpp}
 *
 * This adapter keeps the ACAS ECM/key and MMT/TLV descrambling path, but writes
 * the original TLV stream back out instead of using dantto4k's MPEG-2 TS remux.
 */
#include "aribb61/arib_std_b61.h"
#include <memory>
#include <limits>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "sections.h"
#include "state.h"

namespace {

constexpr uint8_t kTlvSync = 0x7f;
constexpr uint8_t kTlvPacketTypeIpv4 = 0x01;
constexpr uint8_t kTlvPacketTypeIpv6 = 0x02;
constexpr uint8_t kTlvPacketTypeCompressedIp = 0x03;
constexpr uint8_t kTlvPacketTypeControl = 0xfe;
constexpr uint8_t kTlvPacketTypeNull = 0xff;
constexpr uint8_t kMmtpPayloadControlMessage = 0x02;
constexpr uint8_t kMmtTableEcm0 = 0x82;
constexpr uint8_t kMmtTableEcm1 = 0x83;
constexpr uint8_t kMmtTableEmm = 0x84;
constexpr uint8_t kScrambleEven = 0x02;
constexpr uint8_t kScrambleOdd = 0x03;
constexpr size_t kMaxTlvPacketSize = 4 + 0xffff;


uint16_t be16(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t be32(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

bool is_valid_tlv_packet_type(uint8_t packet_type)
{
    switch (packet_type) {
    case kTlvPacketTypeIpv4:
    case kTlvPacketTypeIpv6:
    case kTlvPacketTypeCompressedIp:
    case kTlvPacketTypeControl:
    case kTlvPacketTypeNull:
        return true;
    default:
        return false;
    }
}

bool is_tlv_null_packet(uint8_t packet_type)
{
    return packet_type == kTlvPacketTypeNull;
}

void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

struct MmtpInfo {
    uint16_t packet_id = 0;
    uint32_t sequence = 0;
    uint8_t payload_type = 0;
    uint8_t scramble_flag = 0;
    uint8_t *scramble_control = nullptr;
    uint8_t *extension_length_field = nullptr;
    uint8_t *b61_multi_length_field = nullptr;
    uint8_t *payload_length_field = nullptr;
    bool has_message_authentication = false;
    bool has_initial_counter = false;
    std::array<uint8_t, 16> initial_counter{};
    size_t payload_offset = 0;
    size_t payload_size = 0;
    size_t decrypt_size = 0;
};

bool parse_mmtp(uint8_t *data, size_t size, MmtpInfo& out)
{
    if (size < 12) {
        return false;
    }

    const bool packet_counter = (data[0] & 0x20) != 0;
    const bool extension_header = (data[0] & 0x02) != 0;
    out.payload_type = data[1] & 0x3f;
    out.packet_id = be16(data + 2);
    out.sequence = be32(data + 8);

    size_t pos = 12;
    if (packet_counter) {
        if (size < pos + 4) {
            return false;
        }
        pos += 4;
    }

    if (extension_header) {
        if (size < pos + 4) {
            return false;
        }
        const uint16_t extension_type = be16(data + pos);
        out.extension_length_field = data + pos + 2;
        const uint16_t extension_length = be16(data + pos + 2);
        pos += 4;
        if (size < pos + extension_length) {
            return false;
        }

        if (extension_type == 0x0000) {
            size_t ext_pos = pos;
            const size_t ext_end = pos + extension_length;
            while (ext_end - ext_pos >= 5) {
                const uint16_t multi_type = be16(data + ext_pos) & 0x7fff;
                const bool multi_end = (data[ext_pos] & 0x80) != 0;
                uint8_t *multi_length_field = data + ext_pos + 2;
                const uint16_t multi_length = be16(data + ext_pos + 2);
                ext_pos += 4;
                if (ext_end - ext_pos < multi_length) {
                    return false;
                }

                if (multi_type == 0x0001 && multi_length >= 1) {
                    out.scramble_control = data + ext_pos;
                    out.scramble_flag = (*out.scramble_control & 0x18) >> 3;

                    const bool has_scramble_system_id = (*out.scramble_control & 0x04) != 0;
                    const bool has_message_authentication = (*out.scramble_control & 0x02) != 0;
                    const bool has_initial_counter = (*out.scramble_control & 0x01) != 0;
                    size_t b61_pos = ext_pos + 1;
                    if (has_scramble_system_id) {
                        if (b61_pos >= ext_pos + multi_length) {
                            return false;
                        }
                        ++b61_pos;
                    }
                    if (has_message_authentication) {
                        if (ext_pos + multi_length - b61_pos < 2) {
                            return false;
                        }
                        out.has_message_authentication = true;
                        out.b61_multi_length_field = multi_length_field;
                        out.payload_length_field = data + b61_pos;
                        out.decrypt_size = be16(data + b61_pos);
                        b61_pos += 2;
                    }
                    if (has_initial_counter) {
                        if (ext_pos + multi_length - b61_pos < out.initial_counter.size()) {
                            return false;
                        }
                        std::copy(data + b61_pos,
                                  data + b61_pos + out.initial_counter.size(),
                                  out.initial_counter.begin());
                        out.has_initial_counter = true;
                    }
                }

                ext_pos += multi_length;
                if (multi_end) {
                    break;
                }
            }
        }
        pos += extension_length;
    }

    out.payload_offset = pos;
    out.payload_size = size - pos;
    if (out.has_message_authentication) {
        if (out.decrypt_size > out.payload_size) return false;
    } else {
        out.decrypt_size = out.payload_size;
    }
    return true;
}

void process_signaling_message(const uint8_t *data, size_t size, AcasState& acas, bool emm_enabled)
{
    if (size < 5) {
        return;
    }
    const uint16_t message_id = be16(data);
    if (message_id != 0x8000 && message_id != 0x8001 &&
        message_id != 0x8002 && message_id != 0x8003) {
        return;
    }

    const size_t header_size = message_id == 0x8003 ? 7 : 5;
    if (size < header_size) return;
    const size_t section_size = header_size == 7 ? be32(data + 3) : be16(data + 3);
    if (section_size > size - header_size) return;
    const uint8_t *section = data + header_size;
    if (section_size == 0) {
        return;
    }

    if (section[0] == kMmtTableEcm0 || section[0] == kMmtTableEcm1) {
        std::vector<uint8_t> ecm;
        acas_ecm_metadata metadata;
        if (acas_parse_ecm_section(section, section_size, ecm, metadata)) {
            acas.on_ecm(ecm, metadata);
        }
    } else if (section[0] == kMmtTableEmm && emm_enabled) {
        acas.on_emm_section(section, section_size);
    }
}

struct SignalingFragment {
    uint32_t sequence;
    std::vector<uint8_t> data;
};
// M2 sections are at most 4098 bytes; allow room for message headers and reject
// unbounded hostile fragments. State is keyed by compressed-IP context and PID.
constexpr size_t kMaxSignalingMessage = 8192;
constexpr size_t kMaxFragmentStreams = 256;
void process_signaling_payload(uint32_t stream_id, uint32_t sequence,
                               const uint8_t *payload, size_t size,
                               std::map<uint32_t, SignalingFragment>& fragments,
                               AcasState& acas, bool emm_enabled)
{
    if (size < 2) {
        return;
    }
    const uint8_t fragmentation = (payload[0] & 0xc0) >> 6;
    const bool length_extension = (payload[0] & 0x02) != 0;
    const bool aggregation = (payload[0] & 0x01) != 0;
    if (fragmentation == 0) fragments.erase(stream_id);
    const uint8_t *message_payload = payload + 2;
    size_t message_size = size - 2;

    auto handle_message = [&](const uint8_t *msg, size_t msg_size) {
        if (fragmentation == 0) {
            fragments.erase(stream_id);
            process_signaling_message(msg, msg_size, acas, emm_enabled);
        } else if (fragmentation == 1) {
            fragments.erase(stream_id);
            if (msg_size > kMaxSignalingMessage || fragments.size() >= kMaxFragmentStreams) return;
            fragments.emplace(stream_id, SignalingFragment{sequence, {msg, msg + msg_size}});
        } else {
            auto it = fragments.find(stream_id);
            if (it == fragments.end()) return;
            auto& fragment = it->second;
            if (sequence != fragment.sequence + uint32_t{1} ||
                msg_size > kMaxSignalingMessage - fragment.data.size()) {
                fragments.erase(it);
                return;
            }
            fragment.sequence = sequence;
            fragment.data.insert(fragment.data.end(), msg, msg + msg_size);
            if (fragmentation == 3) {
                process_signaling_message(fragment.data.data(), fragment.data.size(), acas, emm_enabled);
                fragments.erase(it);
            }
        }
    };

    if (!aggregation) {
        handle_message(message_payload, message_size);
        return;
    }

    if (fragmentation != 0) {
        fragments.erase(stream_id);
        return;
    }
    size_t pos = 0;
    while (pos < message_size) {
        size_t length_size = length_extension ? 4 : 2;
        if (message_size - pos < length_size) {
            break;
        }
        uint32_t length = length_extension ? be32(message_payload + pos) : be16(message_payload + pos);
        pos += length_size;
        if (message_size - pos < length) {
            break;
        }
        process_signaling_message(message_payload + pos, length, acas, emm_enabled);
        pos += length;
    }
}

using acas_output_callback = int (*)(void*, const uint8_t*, size_t);

class Passthrough {
public:
    explicit Passthrough(std::unique_ptr<AcasCardClient> card = make_acas_card_client())
        : acas(std::move(card)) {}
    ARIB_STD_B61_STATISTICS stats{};
    bool emm_enabled = false;
    void set_proxy(const std::string& address)
    {
        acas.set_proxy(address);
    }

    void set_strip(bool strip)
    {
        strip_null_packets = strip;
    }

    int process(const uint8_t *data, size_t size, acas_output_callback output, void *opaque)
    {
        if (size) buffer.insert(buffer.end(), data, data + size);
        return drain(output, opaque, false);
    }

    int flush(acas_output_callback output, void *opaque)
    {
        return drain(output, opaque, true);
    }

private:
    int drain(acas_output_callback output, void *opaque, bool flush)
    {
        while (!buffer.empty()) {
            if (buffer[0] != kTlvSync) {
                auto it = std::find(buffer.begin() + 1, buffer.end(), kTlvSync);
                size_t raw_size = it == buffer.end() ? buffer.size() : static_cast<size_t>(it - buffer.begin());
                if (output(opaque, buffer.data(), raw_size) < 0) {
                    return -1;
                }
                buffer.erase(buffer.begin(), buffer.begin() + raw_size);
                continue;
            }

            if (buffer.size() < 4) {
                break;
            }
            const uint8_t packet_type = buffer[1];
            if (!is_valid_tlv_packet_type(packet_type)) {
                if (output(opaque, buffer.data(), 1) < 0) {
                    return -1;
                }
                buffer.erase(buffer.begin());
                continue;
            }

            const size_t packet_size = 4 + be16(buffer.data() + 2);
            if (packet_size > kMaxTlvPacketSize) {
                if (output(opaque, buffer.data(), 1) < 0) {
                    return -1;
                }
                buffer.erase(buffer.begin());
                continue;
            }
            if (buffer.size() < packet_size) {
                break;
            }
            if (strip_null_packets && is_tlv_null_packet(packet_type)) {
                buffer.erase(buffer.begin(), buffer.begin() + packet_size);
                continue;
            }

            std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + packet_size);
            ++stats.total_packet_count;
            process_tlv(packet);
            if (output(opaque, packet.data(), packet.size()) < 0) {
                return -1;
            }
            buffer.erase(buffer.begin(), buffer.begin() + packet_size);
        }

        if (flush && !buffer.empty()) {
            if (output(opaque, buffer.data(), buffer.size()) < 0) {
                return -1;
            }
            buffer.clear();
        }
        return 0;
    }

    void process_tlv(std::vector<uint8_t>& packet)
    {
        const size_t packet_size = packet.size();
        if (packet_size < 7 || packet[1] != kTlvPacketTypeCompressedIp) {
            return;
        }

        uint8_t *tlv_data = packet.data() + 4;
        size_t tlv_size = packet_size - 4;
        if (tlv_size < 3) {
            return;
        }

        size_t pos = 3;
        const uint8_t header_type = tlv_data[2];
        if (header_type != 0x60 && header_type != 0x61) return;
        const uint32_t context_id = be16(tlv_data) >> 4;
        if (header_type == 0x60) {
            pos += 42;
        }
        if (tlv_size <= pos) {
            return;
        }

        uint8_t *mmtp = tlv_data + pos;
        size_t mmtp_size = tlv_size - pos;
        MmtpInfo info;
        if (!parse_mmtp(mmtp, mmtp_size, info)) {
            return;
        }

        uint8_t *payload = mmtp + info.payload_offset;


        const bool encrypted = info.scramble_flag == kScrambleEven ||
                               info.scramble_flag == kScrambleOdd;
        if (encrypted) {
            if (!acas.decrypt_payload(info.scramble_flag, info.packet_id, info.sequence,
                                      payload, info.payload_size, info.decrypt_size,
                                      info.has_initial_counter ? &info.initial_counter : nullptr)) {
                ++stats.undecrypted_packet_count;
                return;
            }
            ++stats.decrypted_packet_count;
            if (info.scramble_control) {
                *info.scramble_control &= static_cast<uint8_t>(~0x18);
            }
        }

        if (info.payload_type == kMmtpPayloadControlMessage) {
            process_signaling_payload((context_id << 16) | info.packet_id, info.sequence,
                                      payload, info.payload_size, fragments, acas, emm_enabled);
        }

        /*
         * The encryption and message-authentication flags are independent.
         * A broadcaster can switch a service to clear payloads while retaining
         * the authentication field.  Strip that field for both encrypted and
         * clear packets so downstream remuxers never consume the authentication
         * bytes as media payload.
         */
        if (info.has_message_authentication && info.scramble_control &&
            info.extension_length_field && info.b61_multi_length_field &&
            info.payload_length_field) {
            const size_t payload_abs = static_cast<size_t>(payload - packet.data());
            const size_t payload_length_abs = static_cast<size_t>(info.payload_length_field - packet.data());
            const size_t auth_size = info.payload_size - info.decrypt_size;
            const uint16_t extension_length = be16(info.extension_length_field);
            const uint16_t b61_multi_length = be16(info.b61_multi_length_field);
            if (extension_length >= 2 && b61_multi_length >= 3 &&
                payload_abs + info.payload_size <= packet.size()) {
                put_be16(info.extension_length_field, extension_length - 2);
                put_be16(info.b61_multi_length_field, b61_multi_length - 2);
                *info.scramble_control &= static_cast<uint8_t>(~0x02);

                if (auth_size > 0) {
                    packet.erase(packet.begin() + payload_abs + info.decrypt_size,
                                 packet.begin() + payload_abs + info.payload_size);
                }
                packet.erase(packet.begin() + payload_length_abs,
                             packet.begin() + payload_length_abs + 2);
                put_be16(packet.data() + 2, static_cast<uint16_t>(packet.size() - 4));
            }
        }
    }

    AcasState acas;
    std::vector<uint8_t> buffer;
    std::map<uint32_t, SignalingFragment> fragments;
    bool strip_null_packets = false;
};

} // namespace

struct ARIB_STD_B61 {
    explicit ARIB_STD_B61(std::unique_ptr<AcasCardClient> card = make_acas_card_client())
        : impl(std::make_unique<Passthrough>(std::move(card))) {}
    std::unique_ptr<Passthrough> impl;
    std::vector<uint8_t> output, borrowed;
    std::string proxy;
    bool strip = false, emm = false, started = false, failed = false;
};

namespace {
template<class F> int guarded(ARIB_STD_B61 *ctx, F action) noexcept {
    if (!ctx) return ARIB_STD_B61_ERROR_INVALID_PARAM;
    if (ctx->failed) return ARIB_STD_B61_ERROR_STATE;
    try { return action(); }
    catch (const std::bad_alloc&) { ctx->failed = true; return ARIB_STD_B61_ERROR_NO_MEMORY; }
    catch (...) { ctx->failed = true; return ARIB_STD_B61_ERROR_PROCESS; }
}
int collect(void *opaque, const uint8_t *data, size_t size) {
    auto& output = static_cast<ARIB_STD_B61*>(opaque)->output;
    if (size > UINT32_MAX - output.size()) throw std::bad_alloc();
    output.insert(output.end(), data, data + size);
    return 0;
}
}
extern "C" ARIB_STD_B61 *create_arib_std_b61(void) {
    try { return new ARIB_STD_B61; } catch (...) { return nullptr; }
}
extern "C" void arib_std_b61_release(ARIB_STD_B61 *ctx) { delete ctx; }
extern "C" int arib_std_b61_put(ARIB_STD_B61 *ctx, const ARIB_STD_B61_BUFFER *buf) {
    if (!buf || (buf->size && !buf->data)) return ARIB_STD_B61_ERROR_INVALID_PARAM;
    return guarded(ctx, [&] {
        ctx->borrowed.clear();
        ctx->started = ctx->started || buf->size != 0;
        auto before = ctx->impl->stats.undecrypted_packet_count;
        ctx->impl->process(buf->data, buf->size, collect, ctx);
        return ctx->impl->stats.undecrypted_packet_count != before ? 1 : 0;
    });
}
extern "C" int arib_std_b61_get(ARIB_STD_B61 *ctx, ARIB_STD_B61_BUFFER *buf) {
    if (!buf) return ARIB_STD_B61_ERROR_INVALID_PARAM;
    buf->data = nullptr; buf->size = 0;
    return guarded(ctx, [&] {
        ctx->borrowed.clear(); ctx->borrowed.swap(ctx->output);
        buf->size = static_cast<uint32_t>(ctx->borrowed.size());
        buf->data = buf->size ? ctx->borrowed.data() : nullptr;
        return 0;
    });
}
extern "C" int arib_std_b61_flush(ARIB_STD_B61 *ctx) {
    return guarded(ctx, [&] {
        ctx->borrowed.clear();
        auto before = ctx->impl->stats.undecrypted_packet_count;
        ctx->impl->flush(collect, ctx);
        return ctx->impl->stats.undecrypted_packet_count != before ? 1 : 0;
    });
}
extern "C" int arib_std_b61_reset(ARIB_STD_B61 *ctx) {
    if (!ctx) return ARIB_STD_B61_ERROR_INVALID_PARAM;
    ctx->failed = false;
    return guarded(ctx, [&] {
        auto fresh = std::make_unique<Passthrough>();
        if (!ctx->proxy.empty()) fresh->set_proxy(ctx->proxy);
        fresh->set_strip(ctx->strip); fresh->emm_enabled = ctx->emm;
        ctx->impl = std::move(fresh);
        ctx->output.clear(); ctx->borrowed.clear(); ctx->started = false;
        return 0;
    });
}
extern "C" int arib_std_b61_set_strip(ARIB_STD_B61 *ctx, int enabled) {
    return guarded(ctx, [&] {
        if (ctx->started) return -4;
        ctx->strip = enabled != 0; ctx->impl->set_strip(ctx->strip); return 0;
    });
}
extern "C" int arib_std_b61_set_emm_proc(ARIB_STD_B61 *ctx, int enabled) {
    return guarded(ctx, [&] {
        if (ctx->started) return -4;
        ctx->emm = enabled != 0; ctx->impl->emm_enabled = ctx->emm; return 0;
    });
}
extern "C" int arib_std_b61_set_cas_proxy(ARIB_STD_B61 *ctx, const char *address) {
    if (!address) return ARIB_STD_B61_ERROR_INVALID_PARAM;
    return guarded(ctx, [&] {
        if (ctx->started) return -4;
        ctx->impl->set_proxy(address); ctx->proxy = address; return 0;
    });
}
extern "C" int arib_std_b61_get_statistics(const ARIB_STD_B61 *ctx, ARIB_STD_B61_STATISTICS *stats) {
    if (!ctx || !stats) return ARIB_STD_B61_ERROR_INVALID_PARAM;
    *stats = ctx->impl->stats; return 0;
}

// Internal dependency injection for stream-boundary tests; not part of the C ABI.
ARIB_STD_B61 *aribb61_create_with_card(std::unique_ptr<AcasCardClient> card) {
    return new ARIB_STD_B61(std::move(card));
}
