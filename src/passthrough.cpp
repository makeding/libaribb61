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
#include "routing_state.h"

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
    bool has_scramble_method = false;
    uint8_t scramble_method = 0;
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
                const uint16_t multi_length = be16(data + ext_pos + 2);
                ext_pos += 4;
                if (ext_end - ext_pos < multi_length) {
                    return false;
                }

                if (multi_type == 0x0001 && multi_length >= 1) {
                    if (out.scramble_control) return false;
                    out.scramble_control = data + ext_pos;
                    out.scramble_flag = (*out.scramble_control & 0x18) >> 3;

                    const bool has_scramble_method = (*out.scramble_control & 0x04) != 0;
                    const bool has_message_authentication = (*out.scramble_control & 0x02) != 0;
                    const bool has_initial_counter = (*out.scramble_control & 0x01) != 0;
                    size_t b61_pos = ext_pos + 1;
                    out.has_scramble_method = has_scramble_method;
                    out.has_message_authentication = has_message_authentication;
                    if (has_scramble_method) {
                        if (b61_pos >= ext_pos + multi_length) {
                            return false;
                        }
                        out.scramble_method = data[b61_pos++];
                    }
                    if (has_message_authentication) {
                        if (ext_pos + multi_length - b61_pos < 2) {
                            return false;
                        }
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

void process_signaling_message(uint32_t stream_id, const uint8_t *data, size_t size,
                               AcasState& acas, RoutingState& routes, bool emm_enabled)
{
    if (size < 5) {
        return;
    }
    const uint16_t message_id = be16(data);
    if (message_id == 0) {
        std::vector<MptSnapshot> snapshots;
        if (acas_parse_pa_message(data, size, snapshots) && routes.update_mpts(stream_id, snapshots)) {
            uint16_t ca_system;
            if (acas.get_ca_system_id(ca_system)) acas.retain_ecm_streams(routes.ecm_streams(ca_system));
            else acas.retain_ecm_streams({});
        }
        return;
    }
    if (message_id != 0x8000 && message_id != 0x8001) {
        return;
    }

    constexpr size_t header_size = 5;
    if (size < header_size) return;
    const size_t section_size = be16(data + 3);
    if (section_size != size - header_size) return;
    const uint8_t *section = data + header_size;
    if (section_size == 0) {
        return;
    }

    if (message_id == 0x8001) {
        MhCatSnapshot snapshot;
        if (acas_parse_mh_cat(section, section_size, snapshot)) {
            routes.update_cat(stream_id, snapshot);
        }
        return;
    }

    if (section[0] == kMmtTableEcm0 || section[0] == kMmtTableEcm1) {
        std::vector<uint8_t> ecm;
        acas_ecm_metadata metadata;
        if (acas_parse_ecm_section(section, section_size, ecm, metadata)) {
            uint16_t ca_system;
            if (!acas.get_ca_system_id(ca_system)) {
                acas.invalidate_ecm_stream(stream_id);
            } else if (routes.ecm_streams(ca_system).contains(stream_id)) {
                acas.on_ecm(stream_id, ecm, metadata);
            }
        }
    } else if (section[0] == kMmtTableEmm && emm_enabled) {
        uint16_t ca_system;
        if (acas.get_ca_system_id(ca_system) && routes.allows_emm(stream_id, ca_system))
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
                               AcasState& acas, RoutingState& routes, bool emm_enabled)
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
            process_signaling_message(stream_id, msg, msg_size, acas, routes, emm_enabled);
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
                process_signaling_message(stream_id, fragment.data.data(), fragment.data.size(), acas, routes, emm_enabled);
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
        process_signaling_message(stream_id, message_payload + pos, length, acas, routes, emm_enabled);
        pos += length;
    }
}

using acas_output_callback = int (*)(void*, const uint8_t*, size_t);

class Passthrough {
public:
    explicit Passthrough(std::unique_ptr<AcasCardClient> card = make_acas_card_client())
        : acas(std::move(card)) {}
    void set_verbose(bool enabled) { acas.set_verbose(enabled); }
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
        warning_flags = 0;
        const auto before = stats.undecrypted_packet_count;
        size_t consumed = 0;
        while (consumed < buffer.size()) {
            const size_t remaining = buffer.size() - consumed;
            const auto begin = buffer.begin() + consumed;
            const auto data = buffer.data() + consumed;
            if (data[0] != kTlvSync) {
                auto it = std::find(begin + 1, buffer.end(), kTlvSync);
                size_t raw_size = it == buffer.end() ? remaining : static_cast<size_t>(it - begin);
                if (output(opaque, data, raw_size) < 0) {
                    return -1;
                }
                consumed += raw_size;
                continue;
            }

            if (remaining < 4) {
                break;
            }
            const uint8_t packet_type = data[1];
            if (!is_valid_tlv_packet_type(packet_type)) {
                if (output(opaque, data, 1) < 0) {
                    return -1;
                }
                ++consumed;
                continue;
            }

            const size_t packet_size = 4 + be16(data + 2);
            if (packet_size > kMaxTlvPacketSize) {
                if (output(opaque, data, 1) < 0) {
                    return -1;
                }
                ++consumed;
                continue;
            }
            if (remaining < packet_size) {
                break;
            }
            if (strip_null_packets && is_tlv_null_packet(packet_type)) {
                consumed += packet_size;
                continue;
            }

            std::vector<uint8_t> packet(begin, begin + packet_size);
            ++stats.total_packet_count;
            process_tlv(packet);
            if (output(opaque, packet.data(), packet.size()) < 0) {
                return -1;
            }
            consumed += packet_size;
        }

        buffer.erase(buffer.begin(), buffer.begin() + consumed);

        if (flush && !buffer.empty()) {
            if (output(opaque, buffer.data(), buffer.size()) < 0) {
                return -1;
            }
            buffer.clear();
        }
        return warning_flags | (stats.undecrypted_packet_count != before ? ARIB_STD_B61_WARN_UNDECRYPTED : 0);
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

        if (header_type == 0x60) {
            if ((tlv_data[3] >> 4) != 6 || tlv_data[7] != 17) return;
            if (routes.update_flow(context_id, tlv_data)) {
                acas.retain_ecm_streams({});
                fragments.clear();
            }
        }

        uint8_t *mmtp = tlv_data + pos;
        size_t mmtp_size = tlv_size - pos;
        MmtpInfo info;
        if (!parse_mmtp(mmtp, mmtp_size, info)) {
            if (info.scramble_flag == kScrambleEven || info.scramble_flag == kScrambleOdd)
                ++stats.undecrypted_packet_count;
            if (info.has_message_authentication) {
                warning_flags |= ARIB_STD_B61_WARN_UNVERIFIED;
                packet.clear();
            }
            return;
        }

        uint8_t *payload = mmtp + info.payload_offset;


        const bool encrypted = info.scramble_flag == kScrambleEven ||
                               info.scramble_flag == kScrambleOdd;
        const uint32_t media_stream = (context_id << 16) | info.packet_id;
        if (info.has_message_authentication ||
            (info.payload_type != kMmtpPayloadControlMessage &&
             routes.authentication_required(media_stream))) {
            warning_flags |= ARIB_STD_B61_WARN_UNVERIFIED;
            if (encrypted) ++stats.undecrypted_packet_count;
            packet.clear();
            return;
        }
        if (encrypted) {
            std::optional<uint32_t> ecm_stream;
            std::optional<ScramblingAlgorithm> packet_algorithm;
            if (info.has_scramble_method) {
                switch (info.scramble_method) {
                case 0x01:
                    packet_algorithm = ScramblingAlgorithm::Aes128Ctr;
                    break;
                case 0x02:
                    packet_algorithm = ScramblingAlgorithm::Camellia128Ctr;
                    break;
                default:
                    ++stats.undecrypted_packet_count;
                    return;
                }
            }
            const auto algorithm = routes.algorithm_for(media_stream, packet_algorithm);
            if (const auto ca_system = acas.ca_system_id())
                ecm_stream = routes.ecm_for(media_stream, *ca_system);
            if (info.payload_type != 0 || !algorithm || !ecm_stream ||
                !acas.decrypt_payload(*ecm_stream, *algorithm, info.scramble_flag, info.packet_id, info.sequence,
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
                                      payload, info.payload_size, fragments, acas, routes, emm_enabled);
        }


    }

    AcasState acas;
    RoutingState routes;
    int warning_flags = 0;
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
    bool verbose = false, strip = false, emm = false, started = false, failed = false;
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
        return ctx->impl->process(buf->data, buf->size, collect, ctx);
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
        return ctx->impl->flush(collect, ctx);
    });
}
extern "C" int arib_std_b61_reset(ARIB_STD_B61 *ctx) {
    if (!ctx) return ARIB_STD_B61_ERROR_INVALID_PARAM;
    ctx->failed = false;
    return guarded(ctx, [&] {
        auto fresh = std::make_unique<Passthrough>();
        if (!ctx->proxy.empty()) fresh->set_proxy(ctx->proxy);
        fresh->set_verbose(ctx->verbose);
        fresh->set_strip(ctx->strip); fresh->emm_enabled = ctx->emm;
        ctx->impl = std::move(fresh);
        ctx->output.clear(); ctx->borrowed.clear(); ctx->started = false;
        return 0;
    });
}
extern "C" int arib_std_b61_set_verbose(ARIB_STD_B61 *ctx, int enabled) {
    return guarded(ctx, [&] {
        if (ctx->started) return -4;
        ctx->verbose = enabled != 0; ctx->impl->set_verbose(ctx->verbose); return 0;
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
