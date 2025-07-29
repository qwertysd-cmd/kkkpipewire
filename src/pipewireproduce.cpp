/*
 S PDX-FileCopyrightText: 2022 Aleix *Pol Gonzalez <aleixpol@kde.org>

 SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
 */

#include "pipewireproduce_p.h"

#include <QMutex>
#include <QThreadPool>
#include <logging_record.h>

#include <QDateTime>
#include <memory>
#include <qstringliteral.h>

#include "gifencoder_p.h"
#include "h264vaapiencoder_p.h"
#include "libopenh264encoder_p.h"
#include "libvpxencoder_p.h"
#include "libvpxvp9encoder_p.h"
#include "libwebpencoder_p.h"
#include "libx264encoder_p.h"

#include <stdio.h> // For fwrite, fopen, fclose
#include <time.h>  // For timestamp in logs

extern "C" {
    #include <fcntl.h>
    #include <libavcodec/avcodec.h>
    #include <libavformat/avformat.h>
    #include <libavutil/timestamp.h>
    #include <spa/param/audio/format-utils.h>
    #include <spa/param/format.h>
    #include <pipewire/pipewire.h>
}

Q_DECLARE_METATYPE(std::optional<int>);
Q_DECLARE_METATYPE(std::optional<std::chrono::nanoseconds>);

// File handle for logging to /tmp/log.txt
static FILE* log_file = nullptr;

static void init_log_file() {
    if (!log_file) {
        log_file = fopen("/tmp/log.txt", "a");
        if (!log_file) {
            qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to open /tmp/log.txt for writing";
        } else {
            time_t now = time(nullptr);
            char timestamp[64];
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
            fprintf(log_file, "[%s] Log file initialized\n", timestamp);
            fflush(log_file);
        }
    }
}

static void log_to_file(const char* message) {
    if (log_file) {
        time_t now = time(nullptr);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fflush(log_file);
    }
}

PipeWireProduce::PipeWireProduce(PipeWireBaseEncodedStream::Encoder encoderType, uint nodeId, uint fd, const Fraction &framerate)
: QObject()
, m_nodeId(nodeId)
, m_encoderType(encoderType)
, m_fd(fd)
, m_frameRate(framerate)
, m_sampleRate(44100)
{
    qRegisterMetaType<std::optional<int>>();
    qRegisterMetaType<std::optional<std::chrono::nanoseconds>>();
    init_log_file();
    char log_msg[64];
    snprintf(log_msg, sizeof(log_msg), "PipeWireProduce constructed, encoderType=%d", static_cast<int>(m_encoderType));
    log_to_file(log_msg);
}

PipeWireProduce::~PipeWireProduce()
{
    log_to_file("PipeWireProduce destroyed");
    if (log_file) {
        fclose(log_file);
        log_file = nullptr;
    }
}

void PipeWireProduce::initialize()
{
    m_stream.reset(new PipeWireSourceStream(nullptr));
    m_stream->setMaxFramerate(m_frameRate);

    m_stream->setUsageHint(Encoder::supportsHardwareEncoding() ? PipeWireSourceStream::UsageHint::EncodeHardware
    : PipeWireSourceStream::UsageHint::EncodeSoftware);

    bool created = m_stream->createStream(m_nodeId, m_fd);
    if (!created || !m_stream->error().isEmpty()) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "failed to set up stream for" << m_nodeId << m_stream->error();
        log_to_file("Failed to set up video stream");
        m_error = m_stream->error();
        m_stream.reset(nullptr);
        return;
    }
    connect(m_stream.get(), &PipeWireSourceStream::streamParametersChanged, this, &PipeWireProduce::setupStream);

    m_frameRepeatTimer.reset(new QTimer);
    m_frameRepeatTimer->setSingleShot(true);
    m_frameRepeatTimer->setInterval(100);
    connect(m_frameRepeatTimer.data(), &QTimer::timeout, this, [this]() {
        auto f = m_lastFrame;
        m_lastFrame = {};
        aboutToEncode(f);
        if (!m_encoder->filterFrame(f)) {
            log_to_file("Failed to filter frame");
            return;
        }

        m_pendingFilterFrames++;
        m_passthroughCondition.notify_all();
    });

    log_to_file("Initialized video stream");
}

Fraction PipeWireProduce::maxFramerate() const
{
    return m_maxFramerate;
}

void PipeWireProduce::setMaxFramerate(const Fraction &framerate)
{
    m_maxFramerate = framerate;

    const double framesPerSecond = static_cast<double>(framerate.numerator) / framerate.denominator;
    if (m_frameRepeatTimer) {
        m_frameRepeatTimer->setInterval((1000 / framesPerSecond) * 2);
    }
    if (m_stream) {
        m_stream->setMaxFramerate(framerate);
    }
}

int PipeWireProduce::maxPendingFrames() const
{
    return m_maxPendingFrames;
}

void PipeWireProduce::setMaxPendingFrames(int newMaxBufferSize)
{
    if (newMaxBufferSize < 3) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Maximum pending frame count of " << newMaxBufferSize << " requested. Value must be 3 or higher.";
        log_to_file("Invalid max pending frames requested");
        newMaxBufferSize = 3;
    }
    m_maxPendingFrames = newMaxBufferSize;
}

void PipeWireProduce::setupStream()
{
    qCDebug(PIPEWIRERECORD_LOGGING) << "Setting up stream";
    log_to_file("Setting up stream");
    disconnect(m_stream.get(), &PipeWireSourceStream::streamParametersChanged, this, &PipeWireProduce::setupStream);

    m_encoder = makeEncoder();
    if (!m_encoder) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "No encoder could be created";
        log_to_file("Failed to create encoder");
        return;
    }

    connect(m_stream.get(), &PipeWireSourceStream::stateChanged, this, &PipeWireProduce::stateChanged);
    if (!setupFormat()) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not set up the producing thread";
        log_to_file("Failed to set up producing thread");
        return;
    }

    connect(m_stream.data(), &PipeWireSourceStream::frameReceived, this, &PipeWireProduce::processFrame);

    m_passthroughThread = std::thread([this]() {
        m_passthroughRunning = true;
        log_to_file("Started passthrough thread");
        while (m_passthroughRunning) {
            std::unique_lock<std::mutex> lock(m_passthroughMutex);
            m_passthroughCondition.wait(lock);

            if (!m_passthroughRunning) {
                break;
            }

            auto [filtered, queued] = m_encoder->encodeFrame(m_maxPendingFrames - m_pendingEncodeFrames);
            m_pendingFilterFrames -= filtered;
            m_pendingEncodeFrames += queued;

            m_outputCondition.notify_all();
        }
        log_to_file("Passthrough thread stopped");
    });
    pthread_setname_np(m_passthroughThread.native_handle(), "PipeWireProduce::passthrough");

    m_outputThread = std::thread([this]() {
        m_outputRunning = true;
        log_to_file("Started output thread");
        while (m_outputRunning) {
            std::unique_lock<std::mutex> lock(m_outputMutex);
            m_outputCondition.wait(lock);

            if (!m_outputRunning) {
                break;
            }

            auto received = m_encoder->receivePacket();
            m_pendingEncodeFrames -= received;

            QMetaObject::invokeMethod(this, &PipeWireProduce::handleEncodedFramesChanged, Qt::QueuedConnection);
        }
        log_to_file("Output thread stopped");
    });
    pthread_setname_np(m_outputThread.native_handle(), "PipeWireProduce::output");
}

bool PipeWireProduce::setupFormat()
{
    QString formatName;
    bool isMp4 = false;
    switch (m_encoderType) {
        case PipeWireBaseEncodedStream::H264Main:
        case PipeWireBaseEncodedStream::H264Baseline:
            formatName = QStringLiteral("mp4");
            isMp4 = true;
            log_to_file("Started recording with mp4 format");
            break;
        case PipeWireBaseEncodedStream::VP8:
        case PipeWireBaseEncodedStream::VP9:
            formatName = QStringLiteral("webm");
            log_to_file("Started recording with webm format");
            break;
        case PipeWireBaseEncodedStream::WebP:
            formatName = QStringLiteral("webp");
            log_to_file("Started recording with webp format");
            break;
        case PipeWireBaseEncodedStream::Gif:
            formatName = QStringLiteral("gif");
            log_to_file("Started recording with gif format");
            break;
        default:
            qCWarning(PIPEWIRERECORD_LOGGING) << "Unknown encoder type" << m_encoderType;
            char log_msg[64];
            snprintf(log_msg, sizeof(log_msg), "Unknown encoder type: %d", static_cast<int>(m_encoderType));
            log_to_file(log_msg);
            return false;
    }

    log_to_file("Allocating video output context");
    int ret = avformat_alloc_output_context2(&m_avFormatContext, nullptr, formatName.toUtf8().constData(), m_output.toUtf8().constData());
    if (!m_avFormatContext) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not deduce output format, falling back to WebM";
        log_to_file("Could not deduce output format, falling back to WebM");
        ret = avformat_alloc_output_context2(&m_avFormatContext, nullptr, "webm", m_output.toUtf8().constData());
        if (!m_avFormatContext) {
            qCWarning(PIPEWIRERECORD_LOGGING) << "Could not set up stream";
            log_to_file("Failed to set up stream");
            return false;
        }
    }

    log_to_file("Opening video output file");
    ret = avio_open(&m_avFormatContext->pb, QFile::encodeName(m_output).constData(), AVIO_FLAG_WRITE);
    if (ret < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not open" << m_output << av_err2str(ret);
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Could not open output file: %s", av_err2str(ret));
        log_to_file(log_msg);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
        return false;
    }

    auto videoStream = avformat_new_stream(m_avFormatContext, nullptr);
    if (!videoStream) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not create video stream";
        log_to_file("Failed to create video stream");
        avio_closep(&m_avFormatContext->pb);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
        return false;
    }
    videoStream->id = 0;
    videoStream->start_time = 0;
    if (m_frameRate) {
        videoStream->r_frame_rate.num = m_frameRate.numerator;
        videoStream->r_frame_rate.den = m_frameRate.denominator;
        videoStream->avg_frame_rate = videoStream->r_frame_rate;
    }

    ret = avcodec_parameters_from_context(videoStream->codecpar, m_encoder->avCodecContext());
    if (ret < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Error copying video codec parameters:" << av_err2str(ret);
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Error copying video codec parameters: %s", av_err2str(ret));
        log_to_file(log_msg);
        avio_closep(&m_avFormatContext->pb);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
        return false;
    }

    // Always setup audio stream
    log_to_file("Attempting audio setup");
    const AVCodec *audioCodec = avcodec_find_encoder(AV_CODEC_ID_MP3);
    if (!audioCodec) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "MP3 codec not found";
        log_to_file("MP3 codec not found");
        return false;
    }

    m_audioCodecContext = avcodec_alloc_context3(audioCodec);
    m_audioCodecContext->sample_rate = m_sampleRate;
    av_channel_layout_default(&m_audioCodecContext->ch_layout, m_channels);
    m_audioCodecContext->sample_fmt = AV_SAMPLE_FMT_FLTP;
    m_audioCodecContext->bit_rate = 128000;

    if (m_avFormatContext->oformat->flags & AVFMT_GLOBALHEADER) {
        m_audioCodecContext->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    }

    ret = avcodec_open2(m_audioCodecContext, audioCodec, nullptr);
    if (ret < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not open MP3 codec:" << av_err2str(ret);
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Could not open MP3 codec: %s", av_err2str(ret));
        log_to_file(log_msg);
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }

    // Setup temporary MP3 file
    log_to_file("Allocating MP3 output context");
    ret = avformat_alloc_output_context2(&m_audioFormatContext, nullptr, "mp3", "/tmp/audio.mp3");
    if (!m_audioFormatContext) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not allocate MP3 output context";
        log_to_file("Could not allocate MP3 output context");
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }

    auto audioStream = avformat_new_stream(m_audioFormatContext, nullptr);
    if (!audioStream) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not create MP3 stream";
        log_to_file("Failed to create MP3 stream");
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }
    audioStream->id = 0;
    audioStream->time_base = {1, m_sampleRate};

    ret = avcodec_parameters_from_context(audioStream->codecpar, m_audioCodecContext);
    if (ret < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not copy MP3 codec parameters:" << av_err2str(ret);
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Could not copy MP3 codec parameters: %s", av_err2str(ret));
        log_to_file(log_msg);
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }

    log_to_file("Opening MP3 output file");
    ret = avio_open(&m_audioFormatContext->pb, "/tmp/audio.mp3", AVIO_FLAG_WRITE);
    if (ret < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not open /tmp/audio.mp3:" << av_err2str(ret);
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Could not open MP3 file: %s", av_err2str(ret));
        log_to_file(log_msg);
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }

    ret = avformat_write_header(m_audioFormatContext, nullptr);
    if (ret < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not write MP3 header:" << av_err2str(ret);
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Could not write MP3 header: %s", av_err2str(ret));
        log_to_file(log_msg);
        avio_closep(&m_audioFormatContext->pb);
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }
    log_to_file("Wrote MP3 header successfully");

    log_to_file("Creating PipeWire main loop");
    m_loop = pw_main_loop_new(nullptr);
    if (!m_loop) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to create PipeWire main loop";
        log_to_file("Failed to create PipeWire main loop");
        avio_closep(&m_audioFormatContext->pb);
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }

    log_to_file("Creating PipeWire context");
    pw_context *context = pw_context_new(pw_main_loop_get_loop(m_loop), nullptr, 0);
    if (!context) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to create PipeWire context";
        log_to_file("Failed to create PipeWire context");
        pw_main_loop_destroy(m_loop);
        m_loop = nullptr;
        avio_closep(&m_audioFormatContext->pb);
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }

    log_to_file("Connecting to PipeWire core");
    pw_core *core = pw_context_connect(context, nullptr, 0);
    if (!core) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to connect to PipeWire core";
        log_to_file("Failed to connect to PipeWire core");
        pw_context_destroy(context);
        pw_main_loop_destroy(m_loop);
        m_loop = nullptr;
        avio_closep(&m_audioFormatContext->pb);
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }

    pw_properties *props = pw_properties_new(
        PW_KEY_MEDIA_TYPE, "Audio",
        PW_KEY_MEDIA_CATEGORY, "Capture",
        PW_KEY_MEDIA_ROLE, "Music",
        "stream.capture.sink", "true",
        nullptr);

    log_to_file("Creating audio stream");
    m_audioStream = pw_stream_new(core, "system-audio-monitor-recorder", props);
    if (!m_audioStream) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to create audio stream";
        log_to_file("Failed to create audio stream");
        pw_core_disconnect(core);
        pw_context_destroy(context);
        pw_main_loop_destroy(m_loop);
        m_loop = nullptr;
        avio_closep(&m_audioFormatContext->pb);
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        return false;
    }

    // Start audio loop in a separate thread
    m_audioRunning = true;
    m_audioThread = std::thread([this, core, context]() {
        log_to_file("Started audio thread");
        pw_main_loop_run(m_loop);
        log_to_file("Audio thread stopped");
        pw_stream_destroy(m_audioStream);
        m_audioStream = nullptr;
        pw_core_disconnect(core);
        pw_context_destroy(context);
        pw_main_loop_destroy(m_loop);
        m_loop = nullptr;
        m_audioRunning = false;
    });
    pthread_setname_np(m_audioThread.native_handle(), "PipeWireProduce::audio");

    static const struct pw_stream_events stream_events = {
        .version = PW_VERSION_STREAM_EVENTS,
        .destroy = nullptr,
        .state_changed = [](void *, enum pw_stream_state old, enum pw_stream_state state, const char *error) {
            char log_msg[128];
            snprintf(log_msg, sizeof(log_msg), "Audio stream state changed: %d -> %d, error=%s", old, state, error ? error : "none");
            log_to_file(log_msg);
            if (state == PW_STREAM_STATE_ERROR && error) {
                qCWarning(PIPEWIRERECORD_LOGGING) << "Audio stream error:" << error;
            }
        },
        .control_info = nullptr,
        .io_changed = nullptr,
        .param_changed = [](void *data, uint32_t id, const struct spa_pod *param) {
            if (param == nullptr || id != SPA_PARAM_Format) return;
            struct spa_audio_info_raw format;
            if (spa_format_audio_raw_parse(param, &format) < 0) {
                qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to parse audio format";
                log_to_file("Failed to parse audio format");
                return;
            }
            char log_msg[128];
            snprintf(log_msg, sizeof(log_msg), "Negotiated audio format: %u Hz, %u channels", format.rate, format.channels);
            qCDebug(PIPEWIRERECORD_LOGGING) << log_msg;
            log_to_file(log_msg);
        },
        .add_buffer = nullptr,
        .remove_buffer = nullptr,
        .process = [](void *data) {
            PipeWireProduce *self = static_cast<PipeWireProduce*>(data);
            struct pw_buffer *buf = pw_stream_dequeue_buffer(self->m_audioStream);
            if (!buf) {
                log_to_file("No audio buffer dequeued");
                return;
            }

            struct spa_data *d = &buf->buffer->datas[0];
            if (!d->data || d->chunk->size == 0) {
                log_to_file("Empty audio buffer received");
                pw_stream_queue_buffer(self->m_audioStream, buf);
                return;
            }

            char log_msg[64];
            snprintf(log_msg, sizeof(log_msg), "Processing audio buffer, size: %u", d->chunk->size);
            log_to_file(log_msg);

            AVFrame *frame = av_frame_alloc();
            if (!frame) {
                log_to_file("Failed to allocate AVFrame");
                pw_stream_queue_buffer(self->m_audioStream, buf);
                return;
            }

            frame->sample_rate = self->m_audioCodecContext->sample_rate;
            av_channel_layout_copy(&frame->ch_layout, &self->m_audioCodecContext->ch_layout);
            frame->format = self->m_audioCodecContext->sample_fmt;
            frame->nb_samples = d->chunk->size / (self->m_audioCodecContext->ch_layout.nb_channels * av_get_bytes_per_sample(self->m_audioCodecContext->sample_fmt));

            int ret = av_frame_get_buffer(frame, 0);
            if (ret >= 0) {
                memcpy(frame->data[0], d->data, d->chunk->size);
                ret = avcodec_send_frame(self->m_audioCodecContext, frame);
                if (ret >= 0) {
                    AVPacket *packet = av_packet_alloc();
                    while (ret >= 0) {
                        ret = avcodec_receive_packet(self->m_audioCodecContext, packet);
                        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) break;
                        if (ret < 0) {
                            char err_msg[128];
                            snprintf(err_msg, sizeof(err_msg), "Audio encoding error: %s", av_err2str(ret));
                            qCWarning(PIPEWIRERECORD_LOGGING) << err_msg;
                            log_to_file(err_msg);
                            break;
                        }
                        packet->stream_index = 0;
                        av_packet_rescale_ts(packet, self->m_audioCodecContext->time_base, self->m_audioFormatContext->streams[0]->time_base);
                        ret = av_interleaved_write_frame(self->m_audioFormatContext, packet);
                        if (ret < 0) {
                            char err_msg[128];
                            snprintf(err_msg, sizeof(err_msg), "Error writing MP3 packet: %s", av_err2str(ret));
                            qCWarning(PIPEWIRERECORD_LOGGING) << err_msg;
                            log_to_file(err_msg);
                        }
                    }
                    av_packet_free(&packet);
                }
            }
            av_frame_free(&frame);
            pw_stream_queue_buffer(self->m_audioStream, buf);
        },
        .drained = nullptr,
        .command = nullptr,
        .trigger_done = nullptr
    };

    spa_hook listener = {};
    pw_stream_add_listener(m_audioStream, &listener, &stream_events, this);

    uint8_t buffer[1024];
    spa_pod_builder b = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
    const spa_pod *params[1];
    struct spa_audio_info_raw audio_format = {};
    audio_format.format = SPA_AUDIO_FORMAT_S16_LE;
    audio_format.rate = static_cast<uint32_t>(m_sampleRate);
    audio_format.channels = static_cast<uint32_t>(m_channels);
    params[0] = spa_format_audio_raw_build(&b, SPA_PARAM_EnumFormat, &audio_format);

    log_to_file("Connecting audio stream");
    if (pw_stream_connect(m_audioStream,
        PW_DIRECTION_INPUT,
        PW_ID_ANY,
        static_cast<pw_stream_flags>(PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_RT_PROCESS),
                          params, 1) < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to connect audio stream";
    log_to_file("Failed to connect audio stream");
    pw_stream_destroy(m_audioStream);
    m_audioStream = nullptr;
    pw_core_disconnect(core);
    pw_context_destroy(context);
    pw_main_loop_destroy(m_loop);
    m_loop = nullptr;
    avio_closep(&m_audioFormatContext->pb);
    avformat_free_context(m_audioFormatContext);
    m_audioFormatContext = nullptr;
    avcodec_free_context(&m_audioCodecContext);
    m_audioCodecContext = nullptr;
    return false;
                          }
                          log_to_file("Audio stream connected");

                          AVDictionary *options = nullptr;
                          if (m_avFormatContext->oformat->video_codec == AV_CODEC_ID_GIF || m_avFormatContext->oformat->video_codec == AV_CODEC_ID_WEBP) {
                              av_dict_set_int(&options, "loop", 0, 0);
                          }
                          ret = avformat_write_header(m_avFormatContext, &options);
                          if (ret < 0) {
                              qCWarning(PIPEWIRERECORD_LOGGING) << "Error writing video header:" << av_err2str(ret);
                              char log_msg[128];
                              snprintf(log_msg, sizeof(log_msg), "Error writing video header: %s", av_err2str(ret));
                              log_to_file(log_msg);
                              if (m_audioStream) {
                                  pw_stream_destroy(m_audioStream);
                                  m_audioStream = nullptr;
                              }
                              if (m_loop) {
                                  pw_main_loop_quit(m_loop);
                                  if (m_audioThread.joinable()) {
                                      m_audioThread.join();
                                  }
                                  pw_main_loop_destroy(m_loop);
                                  m_loop = nullptr;
                              }
                              if (m_audioFormatContext) {
                                  avio_closep(&m_audioFormatContext->pb);
                                  avformat_free_context(m_audioFormatContext);
                                  m_audioFormatContext = nullptr;
                              }
                              if (m_audioCodecContext) {
                                  avcodec_free_context(&m_audioCodecContext);
                                  m_audioCodecContext = nullptr;
                              }
                              avio_closep(&m_avFormatContext->pb);
                              avformat_free_context(m_avFormatContext);
                              m_avFormatContext = nullptr;
                              return false;
                          }
                          log_to_file("Wrote video header successfully");

                          return true;
}

void PipeWireProduce::deactivate()
{
    m_deactivated = true;

    auto streamState = PW_STREAM_STATE_PAUSED;
    if (m_stream) {
        streamState = m_stream->state();
        m_stream->setActive(false);
    }

    if (!m_encoder || streamState != PW_STREAM_STATE_STREAMING) {
        QMetaObject::invokeMethod(this, &PipeWireProduce::destroy, Qt::QueuedConnection);
    }
    log_to_file("Deactivated stream");
}

void PipeWireProduce::destroy()
{
    Q_ASSERT_X(QThread::currentThread() == thread(), "PipeWireProduce", "destroy() called from a different thread than PipeWireProduce's thread");

    if (!m_stream) {
        return;
    }

    m_frameRepeatTimer->stop();

    if (m_passthroughThread.joinable()) {
        m_passthroughRunning = false;
        m_passthroughCondition.notify_all();
        m_passthroughThread.join();
    }

    if (m_outputThread.joinable()) {
        m_outputRunning = false;
        m_outputCondition.notify_all();
        m_outputThread.join();
    }

    if (m_audioThread.joinable()) {
        if (m_loop) {
            pw_main_loop_quit(m_loop);
            m_audioThread.join();
        }
    }

    m_stream.reset();

    qCDebug(PIPEWIRERECORD_LOGGING) << "finished";
    log_to_file("Finished, cleaning up");
    cleanup();
    QThread::currentThread()->quit();
}

void PipeWireProduce::setQuality(const std::optional<quint8> &quality)
{
    m_quality = quality;
    if (m_encoder) {
        m_encoder->setQuality(quality);
    }
    log_to_file("Set quality");
}

void PipeWireProduce::setEncodingPreference(const PipeWireBaseEncodedStream::EncodingPreference &encodingPreference)
{
    m_encodingPreference = encodingPreference;

    if (m_encoder) {
        m_encoder->setEncodingPreference(encodingPreference);
    }
    log_to_file("Set encoding preference");
}

void PipeWireProduce::processFrame(const PipeWireFrame &frame)
{
    auto f = frame;

    m_lastFrame = frame;
    m_frameRepeatTimer->start();

    if (frame.cursor) {
        m_cursor.position = frame.cursor->position;
        m_cursor.hotspot = frame.cursor->hotspot;
        if (!frame.cursor->texture.isNull()) {
            m_cursor.dirty = true;
            m_cursor.texture = frame.cursor->texture;
        }
    }

    auto pts = framePts(frame.presentationTimestamp);
    if (m_previousPts >= 0 && pts <= m_previousPts) {
        return;
    }

    auto frameTime = 1000.0 / (m_maxFramerate.numerator / m_maxFramerate.denominator);
    if ((pts - m_previousPts) < frameTime) {
        return;
    }

    if (m_pendingFilterFrames + 1 > m_maxPendingFrames) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Filter queue is full, dropping frame" << pts;
        char log_msg[64];
        snprintf(log_msg, sizeof(log_msg), "Filter queue full, dropping frame: %ld", pts);
        log_to_file(log_msg);
        return;
    }

    aboutToEncode(f);
    if (!m_encoder->filterFrame(f)) {
        log_to_file("Failed to filter frame");
        return;
    }

    m_pendingFilterFrames++;
    m_previousPts = pts;

    m_passthroughCondition.notify_all();
    log_to_file("Processed video frame");
}

void PipeWireProduce::stateChanged(pw_stream_state state)
{
    if (state != PW_STREAM_STATE_PAUSED || !m_deactivated) {
        char log_msg[64];
        snprintf(log_msg, sizeof(log_msg), "Stream state changed to: %d", state);
        log_to_file(log_msg);
        return;
    }
    if (!m_stream) {
        qCDebug(PIPEWIRERECORD_LOGGING) << "finished without a stream";
        log_to_file("Finished without a stream");
        return;
    }

    disconnect(m_stream.data(), &PipeWireSourceStream::frameReceived, this, &PipeWireProduce::processFrame);

    if (m_pendingFilterFrames <= 0 && m_pendingEncodeFrames <= 0) {
        m_encoder->finish();
        QMetaObject::invokeMethod(this, &PipeWireProduce::destroy, Qt::QueuedConnection);
        log_to_file("Finished encoding, destroying");
    } else {
        qCDebug(PIPEWIRERECORD_LOGGING) << "Waiting for frame queues to empty, still pending filter" << m_pendingFilterFrames << "encode" << m_pendingEncodeFrames;
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Waiting for frame queues: filter=%d, encode=%d", m_pendingFilterFrames.load(), m_pendingEncodeFrames.load());
        log_to_file(log_msg);
        m_passthroughCondition.notify_all();
    }
}

void PipeWireProduce::handleEncodedFramesChanged()
{
    if (!m_deactivated) {
        return;
    }

    m_passthroughCondition.notify_all();

    if (m_pendingFilterFrames <= 0) {
        m_encoder->finish();

        if (m_pendingEncodeFrames <= 0) {
            destroy();
        }
    }
    log_to_file("Handled encoded frames changed");
}

void PipeWireProduce::cleanup()
{
    if (m_audioFormatContext) {
        av_write_trailer(m_audioFormatContext);
        avio_closep(&m_audioFormatContext->pb);
        avformat_free_context(m_audioFormatContext);
        m_audioFormatContext = nullptr;
        log_to_file("Closed MP3 format context");
    }

    if (m_audioStream) {
        pw_stream_destroy(m_audioStream);
        m_audioStream = nullptr;
        log_to_file("Destroyed audio stream");
    }
    if (m_audioCodecContext) {
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
        log_to_file("Freed audio codec context");
    }
    if (m_loop) {
        pw_main_loop_destroy(m_loop);
        m_loop = nullptr;
        log_to_file("Destroyed PipeWire main loop");
    }

    // Mux audio and video into final MP4 if MP4 format
    bool isMp4 = (m_encoderType == PipeWireBaseEncodedStream::H264Main || m_encoderType == PipeWireBaseEncodedStream::H264Baseline);
    if (m_avFormatContext && isMp4) {
        AVFormatContext *tempFormatContext = nullptr;
        int ret = avformat_alloc_output_context2(&tempFormatContext, nullptr, "mp4", m_output.toUtf8().constData());
        if (!tempFormatContext) {
            qCWarning(PIPEWIRERECORD_LOGGING) << "Could not allocate final MP4 context";
            log_to_file("Could not allocate final MP4 context");
        } else {
            // Copy video stream
            AVStream *tempVideoStream = avformat_new_stream(tempFormatContext, nullptr);
            if (!tempVideoStream) {
                qCWarning(PIPEWIRERECORD_LOGGING) << "Could not create final video stream";
                log_to_file("Failed to create final video stream");
            } else {
                tempVideoStream->id = 0;
                tempVideoStream->time_base = m_avFormatContext->streams[0]->time_base;
                avcodec_parameters_copy(tempVideoStream->codecpar, m_avFormatContext->streams[0]->codecpar);
            }

            // Open MP3 file and copy audio stream
            AVFormatContext *inputAudioContext = nullptr;
            if (avformat_open_input(&inputAudioContext, "/tmp/audio.mp3", nullptr, nullptr) >= 0) {
                if (avformat_find_stream_info(inputAudioContext, nullptr) >= 0) {
                    AVStream *tempAudioStream = avformat_new_stream(tempFormatContext, nullptr);
                    if (!tempAudioStream) {
                        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not create final audio stream";
                        log_to_file("Failed to create final audio stream");
                    } else {
                        tempAudioStream->id = 1;
                        avcodec_parameters_copy(tempAudioStream->codecpar, inputAudioContext->streams[0]->codecpar);
                        tempAudioStream->time_base = inputAudioContext->streams[0]->time_base;
                    }
                }
            }

            // Open final output file
            ret = avio_open(&tempFormatContext->pb, QFile::encodeName(m_output).constData(), AVIO_FLAG_WRITE);
            if (ret < 0) {
                qCWarning(PIPEWIRERECORD_LOGGING) << "Could not open final MP4 file:" << av_err2str(ret);
                char log_msg[128];
                snprintf(log_msg, sizeof(log_msg), "Could not open final MP4 file: %s", av_err2str(ret));
                log_to_file(log_msg);
            } else {
                ret = avformat_write_header(tempFormatContext, nullptr);
                if (ret < 0) {
                    qCWarning(PIPEWIRERECORD_LOGGING) << "Could not write final MP4 header:" << av_err2str(ret);
                    char log_msg[128];
                    snprintf(log_msg, sizeof(log_msg), "Could not write final MP4 header: %s", av_err2str(ret));
                    log_to_file(log_msg);
                } else {
                    // Copy video packets
                    AVPacket *pkt = av_packet_alloc();
                    av_seek_frame(m_avFormatContext, 0, 0, AVSEEK_FLAG_BACKWARD);
                    while (av_read_frame(m_avFormatContext, pkt) >= 0) {
                        pkt->stream_index = 0;
                        av_packet_rescale_ts(pkt, m_avFormatContext->streams[0]->time_base, tempFormatContext->streams[0]->time_base);
                        av_interleaved_write_frame(tempFormatContext, pkt);
                        av_packet_unref(pkt);
                    }
                    av_packet_free(&pkt);

                    // Copy audio packets
                    if (inputAudioContext) {
                        pkt = av_packet_alloc();
                        av_seek_frame(inputAudioContext, 0, 0, AVSEEK_FLAG_BACKWARD);
                        while (av_read_frame(inputAudioContext, pkt) >= 0) {
                            pkt->stream_index = 1;
                            av_packet_rescale_ts(pkt, inputAudioContext->streams[0]->time_base, tempFormatContext->streams[1]->time_base);
                            av_interleaved_write_frame(tempFormatContext, pkt);
                            av_packet_unref(pkt);
                        }
                        av_packet_free(&pkt);
                    }

                    av_write_trailer(tempFormatContext);
                    log_to_file("Muxed final MP4 successfully");
                }
                avio_closep(&tempFormatContext->pb);
            }
            if (inputAudioContext) {
                avformat_close_input(&inputAudioContext);
            }
            avformat_free_context(tempFormatContext);
        }

        av_write_trailer(m_avFormatContext);
        avio_closep(&m_avFormatContext->pb);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
        log_to_file("Closed video format context");
    } else if (m_avFormatContext) {
        av_write_trailer(m_avFormatContext);
        avio_closep(&m_avFormatContext->pb);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
        log_to_file("Closed video format context");
    }
}

std::unique_ptr<Encoder> PipeWireProduce::makeEncoder()
{
    auto forcedEncoder = qEnvironmentVariable("KPIPEWIRE_FORCE_ENCODER");
    if (!forcedEncoder.isNull()) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Forcing encoder to" << forcedEncoder;
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "Forcing encoder to: %s", forcedEncoder.toUtf8().constData());
        log_to_file(log_msg);
    }

    auto size = m_stream->size();

    switch (m_encoderType) {
        case PipeWireBaseEncodedStream::H264Baseline:
        case PipeWireBaseEncodedStream::H264Main: {
            auto profile = m_encoderType == PipeWireBaseEncodedStream::H264Baseline ? Encoder::H264Profile::Baseline : Encoder::H264Profile::Main;

            if (forcedEncoder.isNull() || forcedEncoder == u"h264_vaapi") {
                auto hardwareEncoder = std::make_unique<H264VAAPIEncoder>(profile, this);
                hardwareEncoder->setQuality(m_quality);
                hardwareEncoder->setEncodingPreference(m_encodingPreference);
                if (hardwareEncoder->initialize(size)) {
                    log_to_file("Initialized H264 VAAPI encoder");
                    return hardwareEncoder;
                }
            }

            if (forcedEncoder.isNull() || forcedEncoder == u"libx264") {
                auto softwareEncoder = std::make_unique<LibX264Encoder>(profile, this);
                softwareEncoder->setQuality(m_quality);
                softwareEncoder->setEncodingPreference(m_encodingPreference);
                if (softwareEncoder->initialize(size)) {
                    log_to_file("Initialized libx264 encoder");
                    return softwareEncoder;
                }
            }

            if (forcedEncoder.isNull() || forcedEncoder == u"libopenh264") {
                auto softwareEncoder = std::make_unique<LibOpenH264Encoder>(profile, this);
                softwareEncoder->setQuality(m_quality);
                softwareEncoder->setEncodingPreference(m_encodingPreference);
                if (softwareEncoder->initialize(size)) {
                    log_to_file("Initialized libopenh264 encoder");
                    return softwareEncoder;
                }
            }
            break;
        }
        case PipeWireBaseEncodedStream::VP8: {
            if (forcedEncoder.isNull() || forcedEncoder == u"libvpx") {
                auto encoder = std::make_unique<LibVpxEncoder>(this);
                encoder->setQuality(m_quality);
                if (encoder->initialize(size)) {
                    log_to_file("Initialized VP8 encoder");
                    return encoder;
                }
            }
            break;
        }
        case PipeWireBaseEncodedStream::VP9: {
            if (forcedEncoder.isNull() || forcedEncoder == u"libvpx-vp9") {
                auto encoder = std::make_unique<LibVpxVp9Encoder>(this);
                encoder->setQuality(m_quality);
                if (encoder->initialize(size)) {
                    log_to_file("Initialized VP9 encoder");
                    return encoder;
                }
            }
            break;
        }
        case PipeWireBaseEncodedStream::Gif: {
            if (forcedEncoder.isNull() || forcedEncoder == u"gif") {
                auto encoder = std::make_unique<GifEncoder>(this);
                if (encoder->initialize(size)) {
                    log_to_file("Initialized GIF encoder");
                    return encoder;
                }
            }
            break;
        }
        case PipeWireBaseEncodedStream::WebP: {
            if (forcedEncoder.isNull() || forcedEncoder == u"libwebp") {
                auto encoder = std::make_unique<LibWebPEncoder>(this);
                encoder->setQuality(m_quality);
                if (encoder->initialize(size)) {
                    log_to_file("Initialized WebP encoder");
                    return encoder;
                }
            }
            break;
        }
        default:
            qCWarning(PIPEWIRERECORD_LOGGING) << "Unknown encoder type" << m_encoderType;
            log_to_file("Unknown encoder type in makeEncoder");
    }

    return nullptr;
}

#include "moc_pipewireproduce_p.cpp"
