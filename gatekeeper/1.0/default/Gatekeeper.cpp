/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "android.hardware.gatekeeper@1.0-service"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <mutex>

#include <log/log.h>

#include "Gatekeeper.h"

// The QSEE gatekeeper never returns a retry timeout (wrong PIN -> ERROR_GENERAL_FAILURE),
// so enforce the AOSP backoff in software, persisted best-effort under /metadata/gatekeeper.
namespace {

struct __attribute__((packed)) ThrottleFailureRecord {
    uint64_t last_checked_ms;   // CLOCK_BOOTTIME ms at the last counted failure
    uint32_t failure_counter;
};

// AOSP backoff, CAPPED at index 8 (30 min) for daily-driver safety:
// 0-4 free, 5 -> 1 min, 6 -> 5 min, 7 -> 15 min, 8+ -> 30 min.
constexpr uint64_t kThrottleTimeout[] = {0, 0, 0, 0, 0, 60000, 300000, 900000, 1800000};
constexpr uint32_t kThrottleMaxIdx = (sizeof(kThrottleTimeout) / sizeof(kThrottleTimeout[0])) - 1;  // 8
constexpr const char* kThrottleDir = "/metadata/gatekeeper";

class Throttle {
  public:
    // Remaining lockout in ms if uid is currently throttled, else 0 (allow attempt).
    uint32_t Check(uint32_t uid) {
        std::lock_guard<std::mutex> lock(mu_);
        ThrottleFailureRecord r = Load(uid);
        if (r.failure_counter == 0) return 0;
        uint64_t timeout = Timeout(r.failure_counter);
        if (timeout == 0) return 0;
        uint64_t now = NowMs();
        uint64_t last = r.last_checked_ms;
        if (now > last && now < last + timeout) {
            return static_cast<uint32_t>(last + timeout - now);  // still locked out
        }
        if (now <= last) {
            // boottime went backwards (reboot/reset): keep the counter, restart
            // the timer, and enforce the full timeout so a reboot cannot bypass it.
            r.last_checked_ms = now;
            Save(uid, r);
            return static_cast<uint32_t>(timeout);
        }
        return 0;  // lockout expired -> allow this attempt
    }

    void OnFailure(uint32_t uid) {
        std::lock_guard<std::mutex> lock(mu_);
        ThrottleFailureRecord r = Load(uid);
        if (r.failure_counter < kThrottleMaxIdx) r.failure_counter++;  // cap escalation level
        r.last_checked_ms = NowMs();
        Save(uid, r);
    }

    void OnSuccess(uint32_t uid) {
        std::lock_guard<std::mutex> lock(mu_);
        cache_[uid] = {0, 0};
        char path[80];
        snprintf(path, sizeof(path), "%s/%u", kThrottleDir, uid);
        unlink(path);  // best effort
    }

  private:
    static uint64_t NowMs() {
        struct timespec ts;
        // CLOCK_BOOTTIME: monotonic, counts suspend, resets to ~0 on reboot.
        clock_gettime(CLOCK_BOOTTIME, &ts);
        return static_cast<uint64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
    }
    static uint64_t Timeout(uint32_t counter) {
        if (counter > kThrottleMaxIdx) counter = kThrottleMaxIdx;
        return kThrottleTimeout[counter];
    }
    ThrottleFailureRecord Load(uint32_t uid) {
        auto it = cache_.find(uid);
        if (it != cache_.end()) return it->second;
        ThrottleFailureRecord r = {0, 0};
        char path[80];
        snprintf(path, sizeof(path), "%s/%u", kThrottleDir, uid);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ThrottleFailureRecord tmp;
            ssize_t n = read(fd, &tmp, sizeof(tmp));
            close(fd);
            // Accept only an exact-size record with a sane counter (ignore corruption).
            if (n == static_cast<ssize_t>(sizeof(tmp)) && tmp.failure_counter <= 1000000) {
                r = tmp;
            }
        }
        cache_[uid] = r;
        return r;
    }
    void Save(uint32_t uid, const ThrottleFailureRecord& r) {
        cache_[uid] = r;       // RAM cache is the source of truth
        mkdir(kThrottleDir, 0700);  // best effort (init pre-creates it; harmless if it exists)
        char tmp[96];
        snprintf(tmp, sizeof(tmp), "%s/%u.tmp", kThrottleDir, uid);
        int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) {
            ALOGW("gatekeeper throttle: persist open failed (errno %d); RAM-only", errno);
            return;  // degrade gracefully, never block the user
        }
        ssize_t n = write(fd, &r, sizeof(r));
        fsync(fd);
        close(fd);
        if (n == static_cast<ssize_t>(sizeof(r))) {
            char dst[80];
            snprintf(dst, sizeof(dst), "%s/%u", kThrottleDir, uid);
            rename(tmp, dst);  // atomic replace
        } else {
            unlink(tmp);
        }
    }

    std::mutex mu_;
    std::map<uint32_t, ThrottleFailureRecord> cache_;
};

Throttle gThrottle;

}  // namespace

namespace android {
namespace hardware {
namespace gatekeeper {
namespace V1_0 {
namespace implementation {

Gatekeeper::Gatekeeper()
{
    int ret = hw_get_module_by_class(GATEKEEPER_HARDWARE_MODULE_ID, NULL, &module);
    device = NULL;

    if (!ret) {
        ret = gatekeeper_open(module, &device);
    }
    if (ret < 0) {
        LOG_ALWAYS_FATAL_IF(ret < 0, "Unable to open GateKeeper HAL");
    }
}

Gatekeeper::~Gatekeeper()
{
    if (device != nullptr) {
        int ret = gatekeeper_close(device);
        if (ret < 0) {
            ALOGE("Unable to close GateKeeper HAL");
        }
    }
    dlclose(module->dso);
}

// Methods from ::android::hardware::gatekeeper::V1_0::IGatekeeper follow.
Return<void> Gatekeeper::enroll(uint32_t uid,
        const hidl_vec<uint8_t>& currentPasswordHandle,
        const hidl_vec<uint8_t>& currentPassword,
        const hidl_vec<uint8_t>& desiredPassword,
        enroll_cb cb)
{
    GatekeeperResponse rsp;
    uint8_t *enrolled_password_handle = nullptr;
    uint32_t enrolled_password_handle_length = 0;

    int ret = device->enroll(device, uid,
            currentPasswordHandle.data(), currentPasswordHandle.size(),
            currentPassword.data(), currentPassword.size(),
            desiredPassword.data(), desiredPassword.size(),
            &enrolled_password_handle, &enrolled_password_handle_length);
    if (!ret) {
        gThrottle.OnSuccess(uid);  // new/changed credential: clear failures
        rsp.data.setToExternal(enrolled_password_handle,
                               enrolled_password_handle_length,
                               true);
        rsp.code = GatekeeperStatusCode::STATUS_OK;
    } else if (ret > 0) {
        rsp.timeout = ret;
        rsp.code = GatekeeperStatusCode::ERROR_RETRY_TIMEOUT;
    } else {
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
    }
    cb(rsp);
    return Void();
}

Return<void> Gatekeeper::verify(uint32_t uid,
                                uint64_t challenge,
                                const hidl_vec<uint8_t>& enrolledPasswordHandle,
                                const hidl_vec<uint8_t>& providedPassword,
                                verify_cb cb)
{
    GatekeeperResponse rsp;

    // Enforce the software lockout before touching the trustlet, since the QSEE
    // gatekeeper never returns a throttle timeout of its own.
    uint32_t lockout = gThrottle.Check(uid);
    if (lockout > 0) {
        rsp.timeout = lockout;
        rsp.code = GatekeeperStatusCode::ERROR_RETRY_TIMEOUT;
        cb(rsp);
        return Void();
    }

    uint8_t *auth_token = nullptr;
    uint32_t auth_token_length = 0;
    bool request_reenroll = false;

    int ret = device->verify(device, uid, challenge,
            enrolledPasswordHandle.data(), enrolledPasswordHandle.size(),
            providedPassword.data(), providedPassword.size(),
            &auth_token, &auth_token_length,
            &request_reenroll);
    if (!ret) {
        gThrottle.OnSuccess(uid);  // correct password: clear the failure record
        rsp.data.setToExternal(auth_token, auth_token_length, true);
        if (request_reenroll) {
            rsp.code = GatekeeperStatusCode::STATUS_REENROLL;
        } else {
            rsp.code = GatekeeperStatusCode::STATUS_OK;
        }
    } else if (ret > 0) {
        rsp.timeout = ret;
        rsp.code = GatekeeperStatusCode::ERROR_RETRY_TIMEOUT;
    } else {
        gThrottle.OnFailure(uid);  // wrong password: escalate the backoff
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
    }
    cb(rsp);
    return Void();
}

Return<void> Gatekeeper::deleteUser(uint32_t uid, deleteUser_cb cb)  {
    GatekeeperResponse rsp;

    if (device->delete_user != nullptr) {
        int ret = device->delete_user(device, uid);
        if (!ret) {
            rsp.code = GatekeeperStatusCode::STATUS_OK;
        } else if (ret > 0) {
            rsp.timeout = ret;
            rsp.code = GatekeeperStatusCode::ERROR_RETRY_TIMEOUT;
        } else {
            rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        }
    } else {
        rsp.code = GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED;
    }
    cb(rsp);
    return Void();
}

Return<void> Gatekeeper::deleteAllUsers(deleteAllUsers_cb cb)  {
    GatekeeperResponse rsp;
    if (device->delete_all_users != nullptr) {
        int ret = device->delete_all_users(device);
        if (!ret) {
            rsp.code = GatekeeperStatusCode::STATUS_OK;
        } else if (ret > 0) {
            rsp.timeout = ret;
            rsp.code = GatekeeperStatusCode::ERROR_RETRY_TIMEOUT;
        } else {
            rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        }
    } else {
        rsp.code = GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED;
    }
    cb(rsp);
    return Void();
}

IGatekeeper* HIDL_FETCH_IGatekeeper(const char* /* name */) {
    return new Gatekeeper();
}

} // namespace implementation
}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android
