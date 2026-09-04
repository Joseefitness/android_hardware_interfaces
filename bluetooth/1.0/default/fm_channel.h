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

#pragma once

#include <hidl/HidlSupport.h>

namespace android {
namespace hardware {
namespace bluetooth {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_vec;

// Broadcom combo chips drive their FM radio with vendor specific HCI commands on
// the very transport the Bluetooth stack uses. This lends it to the FM daemon.
class FmChannel {
  public:
    // Starts listening on the socket init handed to this process. Does nothing
    // when there is no such socket.
    static void Start();

    // Returns true when the packet belongs to the FM radio, in which case the
    // Bluetooth stack must not see it.
    static bool DeliverEvent(const hidl_vec<uint8_t>& event);
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace bluetooth
}  // namespace hardware
}  // namespace android
