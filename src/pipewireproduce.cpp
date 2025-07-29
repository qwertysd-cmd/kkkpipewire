/*
 S PDX-FileCopyrightText: 2022 Ale*ix Pol Gonzalez <aleixpol@kde.org>

 SPDX-License-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
 */

#include "pipewireproduce_p.h"

#include <QMutex>
#include <QPainter>
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

static void log_packet(const AVFormatContext *fmt_ctx, const AVPacket *pkt)
{
    AVRational *time_base = &fmt_ctx->streams[pkt->stream_index]->time_base;

    qCDebug(PIPEWIRERECORD_LOGGING,
            "pts:%s pts_time:%s dts:%s dts_time:%s duration:%s duration_time:%s "
            "stream_index:%d",
            av_ts2str(pkt->pts),
            av_ts2timestr(pkt->pts, time_base),
            av_ts2str(pkt->dts),
            av_ts2timestr(pkt->dts, time_base),
            av_ts2str(pkt->duration),
            av_ts2timestr(pkt->duration, time_base),
            pkt->stream_index);
}

PipeWireProduce::PipeWireProduce(PipeWireBaseEncodedStream::Encoder encoderType, uint nodeId, uint fd, const Fraction &framerate)
: QObject()
, m_nodeId(nodeId)
, m_encoderType(encoderType)
, m_fd(fd)
, m_frameRate(framerate)
{
    qRegisterMetaType<std::optional<int>>();
    qRegisterMetaType<std::optional<std::chrono::nanoseconds>>();
}

PipeWireProduce::~PipeWireProduce()
{
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
            return;
        }

        m_pendingFilterFrames++;
        m_passthroughCondition.notify_all();
    });
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
        newMaxBufferSize = 3;
    }
    m_maxPendingFrames = newMaxBufferSize;
}

void PipeWireProduce::setupStream()
{
    qCDebug(PIPEWIRERECORD_LOGGING) << "Setting up stream";
    disconnect(m_stream.get(), &PipeWireSourceStream::streamParametersChanged, this, &PipeWireProduce::setupStream);

    m_encoder = makeEncoder();
    if (!m_encoder) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "No encoder could be created";
        return;
    }

    connect(m_stream.get(), &PipeWireSourceStream::stateChanged, this, &PipeWireProduce::stateChanged);
    if (!setupFormat()) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not set up the producing thread";
        return;
    }

    connect(m_stream.data(), &PipeWireSourceStream::frameReceived, this, &PipeWireProduce::processFrame);

    m_passthroughThread = std::thread([this]() {
        m_passthroughRunning = true;
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
    });
    pthread_setname_np(m_passthroughThread.native_handle(), "PipeWireProduce::passthrough");

    m_outputThread = std::thread([this]() {
        m_outputRunning = true;
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
    });
    pthread_setname_np(m_outputThread.native_handle(), "PipeWireProduce::output");
}

bool PipeWireProduce::setupFormat()
{
    QString formatName;
    switch (m_encoderType) {
        case PipeWireBaseEncodedStream::H264Main:
        case PipeWireBaseEncodedStream::H264Baseline:
            formatName = QStringLiteral("mp4");
            break;
        case PipeWireBaseEncodedStream::VP8:
        case PipeWireBaseEncodedStream::VP9:
            formatName = QStringLiteral("webm");
            break;
        case PipeWireBaseEncodedStream::WebP:
            formatName = QStringLiteral("webp");
            break;
        case PipeWireBaseEncodedStream::Gif:
            formatName = QStringLiteral("gif");
            break;
        default:
            qCWarning(PIPEWIRERECORD_LOGGING) << "Unknown encoder type" << m_encoderType;
            return false;
    }

    avformat_alloc_output_context2(&m_avFormatContext, nullptr, formatName.toUtf8().constData(), m_output.toUtf8().constData());
    if (!m_avFormatContext) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not deduce output format, falling back to WebM";
        avformat_alloc_output_context2(&m_avFormatContext, nullptr, "webm", m_output.toUtf8().constData());
        if (!m_avFormatContext) {
            qCWarning(PIPEWIRERECORD_LOGGING) << "Could not set up stream";
            return false;
        }
    }

    int ret = avio_open(&m_avFormatContext->pb, QFile::encodeName(m_output).constData(), AVIO_FLAG_WRITE);
    if (ret < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not open" << m_output << av_err2str(ret);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
        return false;
    }

    auto videoStream = avformat_new_stream(m_avFormatContext, nullptr);
    if (!videoStream) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not create video stream";
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
        avio_closep(&m_avFormatContext->pb);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
        return false;
    }

    // Setup audio stream for MP4 only
    if (m_encoderType == PipeWireBaseEncodedStream::H264Main || m_encoderType == PipeWireBaseEncodedStream::H264Baseline) {
        const AVCodec *audioCodec = avcodec_find_encoder(AV_CODEC_ID_AAC);
        if (!audioCodec) {
            qCWarning(PIPEWIRERECORD_LOGGING) << "AAC codec not found";
        } else {
            auto audioStream = avformat_new_stream(m_avFormatContext, nullptr);
            if (!audioStream) {
                qCWarning(PIPEWIRERECORD_LOGGING) << "Could not create audio stream";
            } else {
                audioStream->id = 1;
                audioStream->time_base = {1, m_sampleRate};

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
                    qCWarning(PIPEWIRERECORD_LOGGING) << "Could not open audio codec:" << av_err2str(ret);
                    avcodec_free_context(&m_audioCodecContext);
                    m_audioCodecContext = nullptr;
                } else {
                    ret = avcodec_parameters_from_context(audioStream->codecpar, m_audioCodecContext);
                    if (ret < 0) {
                        qCWarning(PIPEWIRERECORD_LOGGING) << "Could not copy audio codec parameters:" << av_err2str(ret);
                        avcodec_free_context(&m_audioCodecContext);
                        m_audioCodecContext = nullptr;
                    } else {
                        m_loop = pw_main_loop_new(nullptr);
                        if (!m_loop) {
                            qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to create PipeWire main loop";
                            avcodec_free_context(&m_audioCodecContext);
                            m_audioCodecContext = nullptr;
                            avio_closep(&m_avFormatContext->pb);
                            avformat_free_context(m_avFormatContext);
                            m_avFormatContext = nullptr;
                            return false;
                        }

                        pw_context *context = pw_context_new(pw_main_loop_get_loop(m_loop), nullptr, 0);
                        if (!context) {
                            qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to create PipeWire context";
                            pw_main_loop_destroy(m_loop);
                            m_loop = nullptr;
                            avcodec_free_context(&m_audioCodecContext);
                            m_audioCodecContext = nullptr;
                            avio_closep(&m_avFormatContext->pb);
                            avformat_free_context(m_avFormatContext);
                            m_avFormatContext = nullptr;
                            return false;
                        }

                        pw_core *core = pw_context_connect(context, nullptr, 0);
                        if (!core) {
                            qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to connect to PipeWire core";
                            pw_context_destroy(context);
                            pw_main_loop_destroy(m_loop);
                            m_loop = nullptr;
                            avcodec_free_context(&m_audioCodecContext);
                            m_audioCodecContext = nullptr;
                            avio_closep(&m_avFormatContext->pb);
                            avformat_free_context(m_avFormatContext);
                            m_avFormatContext = nullptr;
                            return false;
                        }

                        pw_properties *props = pw_properties_new(
                            PW_KEY_MEDIA_TYPE, "Audio",
                            PW_KEY_MEDIA_CATEGORY, "Capture",
                            PW_KEY_MEDIA_ROLE, "Music",
                            "stream.capture.sink", "true",
                            nullptr);

                        m_audioStream = pw_stream_new(core, "audio-capture", props);
                        if (!m_audioStream) {
                            qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to create audio stream";
                            pw_context_destroy(context);
                            pw_core_disconnect(core);
                            pw_main_loop_destroy(m_loop);
                            m_loop = nullptr;
                            avcodec_free_context(&m_audioCodecContext);
                            m_audioCodecContext = nullptr;
                            avio_closep(&m_avFormatContext->pb);
                            avformat_free_context(m_avFormatContext);
                            m_avFormatContext = nullptr;
                            return false;
                        }

                        m_audioThread = std::thread([this]() {
                            pw_main_loop_run(m_loop);
                        });
                        pthread_setname_np(m_audioThread.native_handle(), "PipeWireProduce::audio");

                        static const pw_stream_events stream_events = {
                            .version = PW_VERSION_STREAM_EVENTS,
                            .process = [](void *data) {
                                PipeWireProduce *self = static_cast<PipeWireProduce*>(data);
                                struct pw_buffer *buf = pw_stream_dequeue_buffer(self->m_audioStream);
                                if (!buf) {
                                    return;
                                }

                                struct spa_data *d = &buf->buffer->datas[0];
                                if (!d->data || d->chunk->size == 0) {
                                    pw_stream_queue_buffer(self->m_audioStream, buf);
                                    return;
                                }

                                AVFrame *frame = av_frame_alloc();
                                if (!frame) {
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
                                                qCWarning(PIPEWIRERECORD_LOGGING) << "Audio encoding error:" << av_err2str(ret);
                                                break;
                                            }
                                            packet->stream_index = 1;
                                            av_packet_rescale_ts(packet, self->m_audioCodecContext->time_base, self->m_avFormatContext->streams[1]->time_base);
                                            log_packet(self->m_avFormatContext, packet);
                                            ret = av_interleaved_write_frame(self->m_avFormatContext, packet);
                                            if (ret < 0) {
                                                qCWarning(PIPEWIRERECORD_LOGGING) << "Error writing audio packet:" << av_err2str(ret);
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
                        struct spa_pod_builder b = { buffer, sizeof(buffer), 0, {}, {} };
                        const struct spa_pod *params[1];
                        struct spa_audio_info_raw audio_format = {};
                        audio_format.format = SPA_AUDIO_FORMAT_S16_LE;
                        audio_format.rate = static_cast<uint32_t>(m_sampleRate);
                        audio_format.channels = static_cast<uint32_t>(m_channels);
                        params[0] = spa_format_audio_raw_build(&b, SPA_PARAM_EnumFormat, &audio_format);

                        if (pw_stream_connect(m_audioStream,
                            PW_DIRECTION_INPUT,
                            PW_ID_ANY,
                            static_cast<pw_stream_flags>(PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_RT_PROCESS),
                                              params, 1) < 0) {
                            qCWarning(PIPEWIRERECORD_LOGGING) << "Failed to connect audio stream";
                        pw_stream_destroy(m_audioStream);
                        m_audioStream = nullptr;
                        pw_context_destroy(context);
                        pw_core_disconnect(core);
                        pw_main_loop_destroy(m_loop);
                        m_loop = nullptr;
                        avcodec_free_context(&m_audioCodecContext);
                        m_audioCodecContext = nullptr;
                        avio_closep(&m_avFormatContext->pb);
                        avformat_free_context(m_avFormatContext);
                        m_avFormatContext = nullptr;
                        return false;
                                              }
                    }
                }
            }
        }
    }

    AVDictionary *options = nullptr;
    if (m_avFormatContext->oformat->video_codec == AV_CODEC_ID_GIF || m_avFormatContext->oformat->video_codec == AV_CODEC_ID_WEBP) {
        av_dict_set_int(&options, "loop", 0, 0);
    }
    ret = avformat_write_header(m_avFormatContext, &options);
    if (ret < 0) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Error writing header:" << av_err2str(ret);
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
        if (m_audioCodecContext) {
            avcodec_free_context(&m_audioCodecContext);
            m_audioCodecContext = nullptr;
        }
        avio_closep(&m_avFormatContext->pb);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
        return false;
    }

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
    cleanup();
    QThread::currentThread()->quit();
}

void PipeWireProduce::setQuality(const std::optional<quint8> &quality)
{
    m_quality = quality;
    if (m_encoder) {
        m_encoder->setQuality(quality);
    }
}

void PipeWireProduce::setEncodingPreference(const PipeWireBaseEncodedStream::EncodingPreference &encodingPreference)
{
    m_encodingPreference = encodingPreference;

    if (m_encoder) {
        m_encoder->setEncodingPreference(encodingPreference);
    }
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
        return;
    }

    aboutToEncode(f);
    if (!m_encoder->filterFrame(f)) {
        return;
    }

    m_pendingFilterFrames++;
    m_previousPts = pts;

    m_passthroughCondition.notify_all();
}

void PipeWireProduce::stateChanged(pw_stream_state state)
{
    if (state != PW_STREAM_STATE_PAUSED || !m_deactivated) {
        return;
    }
    if (!m_stream) {
        qCDebug(PIPEWIRERECORD_LOGGING) << "finished without a stream";
        return;
    }

    disconnect(m_stream.data(), &PipeWireSourceStream::frameReceived, this, &PipeWireProduce::processFrame);

    if (m_pendingFilterFrames <= 0 && m_pendingEncodeFrames <= 0) {
        m_encoder->finish();
        QMetaObject::invokeMethod(this, &PipeWireProduce::destroy, Qt::QueuedConnection);
    } else {
        qCDebug(PIPEWIRERECORD_LOGGING) << "Waiting for frame queues to empty, still pending filter" << m_pendingFilterFrames << "encode"
        << m_pendingEncodeFrames;
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
}

void PipeWireProduce::cleanup()
{
    if (m_audioStream) {
        pw_stream_destroy(m_audioStream);
        m_audioStream = nullptr;
    }
    if (m_audioCodecContext) {
        avcodec_free_context(&m_audioCodecContext);
        m_audioCodecContext = nullptr;
    }
    if (m_loop) {
        pw_main_loop_destroy(m_loop);
        m_loop = nullptr;
    }
    if (m_avFormatContext) {
        if (auto result = av_write_trailer(m_avFormatContext); result < 0) {
            qCWarning(PIPEWIRERECORD_LOGGING) << "Could not write trailer";
        }
        avio_closep(&m_avFormatContext->pb);
        avformat_free_context(m_avFormatContext);
        m_avFormatContext = nullptr;
    }
}

std::unique_ptr<Encoder> PipeWireProduce::makeEncoder()
{
    auto forcedEncoder = qEnvironmentVariable("KPIPEWIRE_FORCE_ENCODER");
    if (!forcedEncoder.isNull()) {
        qCWarning(PIPEWIRERECORD_LOGGING) << "Forcing encoder to" << forcedEncoder;
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
                    return hardwareEncoder;
                }
            }

            if (forcedEncoder.isNull() || forcedEncoder == u"libx264") {
                auto softwareEncoder = std::make_unique<LibX264Encoder>(profile, this);
                softwareEncoder->setQuality(m_quality);
                softwareEncoder->setEncodingPreference(m_encodingPreference);
                if (softwareEncoder->initialize(size)) {
                    return softwareEncoder;
                }
            }

            if (forcedEncoder.isNull() || forcedEncoder == u"libopenh264") {
                auto softwareEncoder = std::make_unique<LibOpenH264Encoder>(profile, this);
                softwareEncoder->setQuality(m_quality);
                softwareEncoder->setEncodingPreference(m_encodingPreference);
                if (softwareEncoder->initialize(size)) {
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
                    return encoder;
                }
            }
            break;
        }
        case PipeWireBaseEncodedStream::Gif: {
            if (forcedEncoder.isNull() || forcedEncoder == u"gif") {
                auto encoder = std::make_unique<GifEncoder>(this);
                if (encoder->initialize(size)) {
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
                    return encoder;
                }
            }
            break;
        }
        default:
            qCWarning(PIPEWIRERECORD_LOGGING) << "Unknown encoder type" << m_encoderType;
    }

    return nullptr;
}

#include "moc_pipewireproduce_p.cpp"
