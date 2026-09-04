//
// Copyright 2016 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "fm_channel.h"

#define LOG_TAG "android.hardware.bluetooth@1.0-impl"
#include <cutils/sockets.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utils/Log.h>

#include <mutex>
#include <thread>

#include "hci_internals.h"
#include "vendor_interface.h"

namespace {

using android::hardware::hidl_vec;
using android::hardware::bluetooth::V1_0::implementation::VendorInterface;

constexpr char kSocketName[] = "fm_hci";

// Message opcodes, one message per datagram in both directions.
constexpr uint8_t kOpAcquire = 0x01;      // ->  power the chip up for FM
constexpr uint8_t kOpRelease = 0x02;      // ->  let go of the chip
constexpr uint8_t kOpCommand = 0x03;      // ->  an FM HCI command to inject
constexpr uint8_t kOpEvent = 0x04;        // <-  an FM HCI event
constexpr uint8_t kOpAcquireDone = 0x81;  // <-  followed by a status byte
constexpr uint8_t kOpReleaseDone = 0x82;  // <-  followed by a status byte

constexpr uint8_t kStatusOk = 0x00;
constexpr uint8_t kStatusFailed = 0x01;

constexpr uint16_t kFmVendorOpcode = 0xfc15;
constexpr uint8_t kVendorSpecificEvent = 0xff;
constexpr uint8_t kFmSubEvent = 0x08;

// A message never carries more than one HCI packet plus its opcode.
constexpr size_t kMaxMessageSize = 260;

// Powering the chip up includes the firmware download, which is the slowest
// thing the transport ever does.
constexpr int kFirmwareTimeoutMs = 15000;

std::mutex g_client_mutex;
int g_client_fd = -1;

void SendMessage(int fd, const uint8_t* data, size_t length) {
    ssize_t sent = TEMP_FAILURE_RETRY(send(fd, data, length, MSG_DONTWAIT | MSG_NOSIGNAL));
    if (sent < 0) {
        ALOGE("%s: dropping a %zu byte message: %s", __func__, length, strerror(errno));
    }
}

void SendStatus(int fd, uint8_t opcode, uint8_t status) {
    uint8_t message[2] = {opcode, status};
    SendMessage(fd, message, sizeof(message));
}

uint8_t Acquire() {
    if (!VendorInterface::AcquireTransport()) {
        ALOGE("%s: unable to open the Bluetooth transport", __func__);
        return kStatusFailed;
    }
    if (!VendorInterface::WaitForFirmwareConfigured(kFirmwareTimeoutMs)) {
        ALOGE("%s: the firmware was not configured", __func__);
        VendorInterface::ReleaseTransport();
        return kStatusFailed;
    }
    return kStatusOk;
}

void ServeClient(int fd) {
    bool acquired = false;

    for (;;) {
        uint8_t message[kMaxMessageSize];
        ssize_t length = TEMP_FAILURE_RETRY(recv(fd, message, sizeof(message), 0));
        if (length <= 0) {
            break;
        }

        switch (message[0]) {
            case kOpAcquire: {
                uint8_t status = acquired ? kStatusOk : Acquire();
                acquired = acquired || status == kStatusOk;
                SendStatus(fd, kOpAcquireDone, status);
                break;
            }

            case kOpRelease: {
                if (acquired) {
                    acquired = false;
                    VendorInterface::ReleaseTransport();
                }
                SendStatus(fd, kOpReleaseDone, kStatusOk);
                break;
            }

            case kOpCommand: {
                if (!acquired || length < 4) {
                    ALOGE("%s: a %zd byte command with the chip %s", __func__, length,
                          acquired ? "up" : "down");
                    break;
                }
                uint16_t opcode = message[1] | (message[2] << 8);
                if (opcode != kFmVendorOpcode) {
                    ALOGE("%s: refusing opcode 0x%04x", __func__, opcode);
                    break;
                }
                VendorInterface* vendor_interface = VendorInterface::get();
                if (vendor_interface != nullptr) {
                    vendor_interface->Send(HCI_PACKET_TYPE_COMMAND, message + 1, length - 1);
                }
                break;
            }

            default:
                ALOGE("%s: unknown message 0x%02x", __func__, message[0]);
                break;
        }
    }

    if (acquired) {
        VendorInterface::ReleaseTransport();
    }
}

void ServerLoop(int server_fd) {
    for (;;) {
        int fd = TEMP_FAILURE_RETRY(accept4(server_fd, nullptr, nullptr, SOCK_CLOEXEC));
        if (fd < 0) {
            ALOGE("%s: accept: %s", __func__, strerror(errno));
            break;
        }

        ALOGI("%s: the FM daemon took the transport", __func__);
        {
            std::lock_guard<std::mutex> lock(g_client_mutex);
            g_client_fd = fd;
        }

        ServeClient(fd);

        {
            std::lock_guard<std::mutex> lock(g_client_mutex);
            g_client_fd = -1;
        }
        close(fd);
        ALOGI("%s: the FM daemon left", __func__);
    }

    close(server_fd);
}

}  // namespace

namespace android {
namespace hardware {
namespace bluetooth {
namespace V1_0 {
namespace implementation {

void FmChannel::Start() {
    static std::once_flag once;

    std::call_once(once, []() {
        int server_fd = android_get_control_socket(kSocketName);
        if (server_fd < 0) {
            ALOGI("No %s socket, the FM radio cannot share the transport", kSocketName);
            return;
        }
        if (listen(server_fd, 1) < 0) {
            ALOGE("listen on %s: %s", kSocketName, strerror(errno));
            close(server_fd);
            return;
        }
        std::thread(ServerLoop, server_fd).detach();
    });
}

bool FmChannel::DeliverEvent(const hidl_vec<uint8_t>& event) {
    const uint8_t* packet = event.data();
    size_t size = event.size();
    bool is_fm = false;

    std::lock_guard<std::mutex> lock(g_client_mutex);

    if (size >= 5 && packet[0] == HCI_COMMAND_COMPLETE_EVENT) {
        uint16_t opcode = packet[3] | (packet[4] << 8);
        is_fm = opcode == kFmVendorOpcode;
    } else if (size >= 3 && packet[0] == kVendorSpecificEvent && packet[2] == kFmSubEvent) {
        is_fm = true;
    }

    if (!is_fm) {
        return false;
    }

    if (g_client_fd < 0) {
        ALOGW("Dropping an FM event 0x%02x with no FM daemon around", packet[0]);
        return true;
    }
    if (size + 1 > kMaxMessageSize) {
        ALOGE("Dropping a %zu byte FM event", size);
        return true;
    }

    uint8_t message[kMaxMessageSize];
    message[0] = kOpEvent;
    memcpy(message + 1, packet, size);
    SendMessage(g_client_fd, message, size + 1);
    return true;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace bluetooth
}  // namespace hardware
}  // namespace android
