#!/usr/bin/env python3
"""Bounded live C-ABI/card/remux/decode check; media stays in memory."""
import argparse
import collections
import ctypes as c
import datetime
import json
import subprocess
import time
import urllib.request


class Buffer(c.Structure):
    _fields_ = [('data', c.POINTER(c.c_uint8)), ('size', c.c_uint32)]


class Statistics(c.Structure):
    _fields_ = [('total', c.c_uint64), ('decrypted', c.c_uint64),
                ('undecrypted', c.c_uint64)]


def run(args, data, report, name):
    result = subprocess.run(args, input=data, capture_output=True, timeout=60)
    report[name] = {'command': args, 'exit': result.returncode,
                    'stderr': result.stderr.decode(errors='replace')}
    if result.returncode:
        report[name]['stdout'] = result.stdout.decode(errors='replace')
        raise RuntimeError(name + ' failed')
    return result.stdout


def check(options, report):
    lib = c.CDLL(options.library)
    lib.create_arib_std_b61.restype = c.c_void_p
    for name, arguments in {
        'set_cas_proxy': [c.c_char_p], 'put': [c.POINTER(Buffer)],
        'get': [c.POINTER(Buffer)], 'get_statistics': [c.POINTER(Statistics)],
        'release': [],
    }.items():
        getattr(lib, 'arib_std_b61_' + name).argtypes = [c.c_void_p] + arguments
    context = lib.create_arib_std_b61()
    if not context:
        raise RuntimeError('decoder creation failed')
    output = bytearray()
    statuses = collections.Counter()
    snapshots = []
    processing_seconds = 0
    received = 0
    started = time.monotonic()
    try:
        if lib.arib_std_b61_set_cas_proxy(context, options.proxy.encode()) != 0:
            raise RuntimeError('proxy configuration failed')
        with urllib.request.urlopen(options.url, timeout=15) as response:
            report['http'] = {'status': response.status,
                              'content_type': response.headers.get('Content-Type')}
            while received < options.mib * 1024 * 1024:
                if time.monotonic() - started > 90:
                    raise RuntimeError('capture exceeded 90 seconds')
                data = response.read(65536)
                if not data:
                    raise RuntimeError('source ended after %d bytes' % received)
                received += len(data)
                array = (c.c_uint8 * len(data)).from_buffer_copy(data)
                buffer = Buffer(array, len(data))
                before = time.monotonic()
                status = lib.arib_std_b61_put(context, c.byref(buffer))
                processing_seconds += time.monotonic() - before
                statuses[status] += 1
                if status < 0:
                    raise RuntimeError('put failed: %d' % status)
                drained = Buffer()
                if lib.arib_std_b61_get(context, c.byref(drained)) != 0:
                    raise RuntimeError('get failed')
                output.extend(c.string_at(drained.data, drained.size))
                if received % (4 * 1024 * 1024) == 0:
                    stats = Statistics()
                    if lib.arib_std_b61_get_statistics(context, c.byref(stats)) != 0:
                        raise RuntimeError('statistics failed')
                    snapshots.append({'input_bytes': received, 'total': stats.total,
                                      'decrypted': stats.decrypted,
                                      'undecrypted': stats.undecrypted})
    finally:
        lib.arib_std_b61_release(context)
        report['b61'] = {'received_bytes': received, 'output_bytes': len(output),
                         'elapsed_seconds': time.monotonic() - started,
                         'processing_seconds': processing_seconds,
                         'statuses': dict(statuses), 'snapshots': snapshots}
    if not snapshots or snapshots[-1]['decrypted'] == 0:
        raise RuntimeError('no packets decrypted')
    if snapshots[-1]['undecrypted'] != snapshots[-2]['undecrypted']:
        raise RuntimeError('encrypted packets persist in final 4 MiB')
    mp4 = run([options.tlvdemux, 'pipe', '-'], output, report, 'remux')
    del output
    report['remux']['bytes'] = len(mp4)
    probe = json.loads(run([
        options.ffprobe, '-v', 'error', '-show_streams', '-show_packets',
        '-show_entries',
        'stream=index,codec_name,codec_type,width,height,sample_rate,channels:'
        'packet=stream_index,pts_time,duration_time', '-of', 'json', '-i', 'pipe:0',
    ], mp4, report, 'probe'))
    report['probe']['streams'] = probe.get('streams', [])
    ranges = {}
    for packet in probe.get('packets', []):
        if 'pts_time' not in packet:
            continue
        track = packet['stream_index']
        start = float(packet['pts_time'])
        end = start + float(packet.get('duration_time', 0))
        previous = ranges.get(track, (start, end, 0))
        ranges[track] = (min(previous[0], start), max(previous[1], end), previous[2] + 1)
    report['probe']['packet_ranges_seconds'] = ranges
    tracks = {stream['codec_type']: stream['index'] for stream in probe.get('streams', [])}
    if 'video' not in tracks or 'audio' not in tracks:
        raise RuntimeError('missing video or audio stream')
    video = ranges[tracks['video']]
    audio = ranges[tracks['audio']]
    overlap = min(video[1], audio[1]) - max(video[0], audio[0])
    report['probe']['av_overlap_seconds'] = overlap
    if overlap < 3:
        raise RuntimeError('less than three seconds of common A/V timestamps')
    run([options.ffmpeg, '-v', 'error', '-xerror', '-i', 'pipe:0', '-t', '3',
         '-map', '0:v:0', '-map', '0:a:0', '-f', 'null', '-'], mp4, report, 'decode')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('library', 'proxy', 'url', 'tlvdemux'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--ffmpeg', default='ffmpeg')
    parser.add_argument('--ffprobe', default='ffprobe')
    parser.add_argument('--mib', type=int, default=32, choices=range(8, 65, 4))
    options = parser.parse_args()
    report = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'options': vars(options)}
    try:
        check(options, report)
        report['passed'] = True
    except Exception as error:
        report['passed'] = False
        report['error'] = str(error)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
