#include "attackshark_device.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QThread>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace attackshark {

namespace {

constexpr int kInterReportDelayMs = 150;
constexpr int kHotplugCheckIntervalMs = 2000;

const uint8_t kPollingRatePayloads[4][2] = {
    {0x08, 0xF7}, // 125 Hz
    {0x04, 0xFB}, // 250 Hz
    {0x02, 0xFD}, // 500 Hz
    {0x01, 0xFE}, // 1000 Hz
};

const uint8_t kBaseColorModes[4][15] = {
    {0x05, 0x0F, 0x01, 0x10, 0x01, 0xA8, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0xC0, 0x00, 0x00}, // Disabled
    {0x05, 0x0F, 0x01, 0x20, 0x01, 0xA8, 0x00, 0x00, 0xFF, 0x01, 0x06, 0x01, 0xCF, 0x00, 0x00}, // Breathing
    {0x05, 0x0F, 0x01, 0x30, 0x01, 0xA8, 0x00, 0x00, 0xFF, 0x01, 0x06, 0x01, 0xDF, 0x00, 0x00}, // Neon
    {0x05, 0x0F, 0x01, 0x40, 0x01, 0xA8, 0x00, 0x00, 0xFF, 0x01, 0x06, 0x01, 0xEF, 0x00, 0x00}, // Color Breathing
};

QString readSysfsLine(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};
    return QString::fromUtf8(f.readLine()).trimmed();
}

struct SysfsHidrawEntry {
    QString hidrawNode; // e.g. /dev/hidraw7
    QString usbDirPath; // canonical USB device sysfs dir (e.g. /sys/devices/.../usb7/7-1)
    QString productName;
    uint16_t vid = 0;
    uint16_t pid = 0;
    int interfaceNumber = -1;
};

QList<SysfsHidrawEntry> scanSysfsHidraw()
{
    QList<SysfsHidrawEntry> entries;
    QDir hidrawClassDir(QStringLiteral("/sys/class/hidraw"));
    const QStringList names = hidrawClassDir.entryList(
        QStringList{QStringLiteral("hidraw*")},
        QDir::Dirs | QDir::NoDotAndDotDot,
        QDir::Name);

    for (const QString &name : names) {
        const QString devSysPath = hidrawClassDir.absoluteFilePath(name + QStringLiteral("/device"));
        const QFileInfo devInfo(devSysPath);
        if (!devInfo.exists())
            continue;

        const QString canonicalDev = devInfo.canonicalFilePath();
        const QString ifaceDir = QFileInfo(canonicalDev + QStringLiteral("/..")).canonicalFilePath();
        const QString usbDir   = QFileInfo(canonicalDev + QStringLiteral("/../..")).canonicalFilePath();

        bool okVid = false, okPid = false, okIface = false;
        const uint16_t vid = static_cast<uint16_t>(readSysfsLine(usbDir + QStringLiteral("/idVendor")).toUInt(&okVid, 16));
        const uint16_t pid = static_cast<uint16_t>(readSysfsLine(usbDir + QStringLiteral("/idProduct")).toUInt(&okPid, 16));
        const int ifaceNum = static_cast<int>(readSysfsLine(ifaceDir + QStringLiteral("/bInterfaceNumber")).toInt(&okIface, 16));

        if (!okVid || !okPid)
            continue;

        QString prod = readSysfsLine(usbDir + QStringLiteral("/product"));
        const QString mfg = readSysfsLine(usbDir + QStringLiteral("/manufacturer"));
        if (prod.isEmpty())
            prod = QStringLiteral("USB HID Device");
        if (!mfg.isEmpty() && !prod.startsWith(mfg, Qt::CaseInsensitive))
            prod = mfg + QStringLiteral(" ") + prod;

        SysfsHidrawEntry entry;
        entry.hidrawNode      = QStringLiteral("/dev/") + name;
        entry.usbDirPath      = usbDir;
        entry.productName     = prod;
        entry.vid             = vid;
        entry.pid             = pid;
        entry.interfaceNumber = okIface ? ifaceNum : -1;
        entries.append(entry);
    }

    return entries;
}

} // namespace

AttackSharkDevice::AttackSharkDevice(QObject *parent)
    : QObject(parent)
{
    m_hotplugTimer = new QTimer(this);
    m_hotplugTimer->setInterval(kHotplugCheckIntervalMs);
    connect(m_hotplugTimer, &QTimer::timeout,
            this, &AttackSharkDevice::checkHotplugTransition);
    m_hotplugTimer->start();
}

AttackSharkDevice::~AttackSharkDevice()
{
    closeDevice();
}

QList<DeviceInfo> AttackSharkDevice::enumerateDevices(bool allHidDevices)
{
    QList<DeviceInfo> result;
    const QList<SysfsHidrawEntry> sysEntries = scanSysfsHidraw();

    for (const SysfsHidrawEntry &e : sysEntries) {
        const bool isAttackShark = isAttackSharkDevice(e.vid, e.pid);

        if (!allHidDevices) {
            if (!isAttackShark || e.interfaceNumber != kConfigInterface)
                continue;
        } else {
            // In "all devices" mode, prefer interface 2 for multi-interface Attack Shark devices
            if (isAttackShark && e.interfaceNumber != kConfigInterface)
                continue;
        }

        DeviceInfo info;
        info.path       = e.hidrawNode;
        info.hidrawPath = e.hidrawNode;
        info.vid        = e.vid;
        info.pid        = e.pid;
        info.isWired    = (e.vid == kVendorId && isWiredPid(e.pid));

        if (isAttackShark) {
            info.name = info.isWired
                ? QStringLiteral("Attack Shark X11 (Wired / Charging)")
                : QStringLiteral("Attack Shark X11 (2.4G Wireless)");
        } else {
            info.name = e.productName;
        }

        result.append(info);
    }

    return result;
}

QString AttackSharkDevice::findDefaultDevicePath()
{
    const QList<DeviceInfo> devices = enumerateDevices(false);
    // Prioritize Wired mode if plugged in (since the mouse turns off its 2.4G radio when charging via USB)
    for (const DeviceInfo &d : devices) {
        if (d.isWired)
            return d.hidrawPath;
    }
    for (const DeviceInfo &d : devices) {
        if (!d.isWired)
            return d.hidrawPath;
    }
    return {};
}

QString AttackSharkDevice::resolveConfigHidrawPath(const QString &devicePath, bool *isWiredOut)
{
    const QList<SysfsHidrawEntry> sysEntries = scanSysfsHidraw();

    // Check if an Attack Shark X11 Wired connection is currently active.
    // When the USB charging cable is plugged in, the mouse switches to Wired USB mode (1d57:fa61)
    // and stops talking to the 2.4G wireless dongle (1d57:fa60), even if the dongle stays plugged in.
    QString activeWiredHidraw;
    QString activeWirelessHidraw;
    for (const SysfsHidrawEntry &e : sysEntries) {
        if (e.vid == kVendorId && e.interfaceNumber == kConfigInterface) {
            if (isWiredPid(e.pid) && activeWiredHidraw.isEmpty()) {
                activeWiredHidraw = e.hidrawNode;
            } else if (e.pid == kProductIdWireless && activeWirelessHidraw.isEmpty()) {
                activeWirelessHidraw = e.hidrawNode;
            }
        }
    }

    // 1. If devicePath is a specific /dev/hidraw* node, inspect what device it belongs to
    if (devicePath.startsWith(QStringLiteral("/dev/hidraw"))) {
        for (const SysfsHidrawEntry &e : sysEntries) {
            if (e.hidrawNode == devicePath) {
                // If the user/settings selected an Attack Shark X11 (e.g. wireless dongle),
                // but the mouse is currently plugged in via USB cable, prioritize the active wired node!
                if (isAttackSharkDevice(e.vid, e.pid) && !activeWiredHidraw.isEmpty()) {
                    if (isWiredOut)
                        *isWiredOut = true;
                    return activeWiredHidraw;
                }
                if (e.interfaceNumber == kConfigInterface) {
                    if (isWiredOut)
                        *isWiredOut = (e.vid == kVendorId && isWiredPid(e.pid));
                    return e.hidrawNode;
                }
                // Find sibling Interface 2 on the same USB device
                for (const SysfsHidrawEntry &sibling : sysEntries) {
                    if (sibling.usbDirPath == e.usbDirPath && sibling.interfaceNumber == kConfigInterface) {
                        if (isWiredOut)
                            *isWiredOut = (sibling.vid == kVendorId && isWiredPid(sibling.pid));
                        return sibling.hidrawNode;
                    }
                }
                break;
            }
        }
    }

    // 2. Fallback / auto-priority: Wired Attack Shark X11 first, then 2.4G Wireless Attack Shark X11
    if (!activeWiredHidraw.isEmpty()) {
        if (isWiredOut)
            *isWiredOut = true;
        return activeWiredHidraw;
    }
    if (!activeWirelessHidraw.isEmpty()) {
        if (isWiredOut)
            *isWiredOut = false;
        return activeWirelessHidraw;
    }

    return {};
}

bool AttackSharkDevice::openDevice(const QString &devicePath)
{
    closeDevice();

    bool wired = false;
    const QString hidraw = resolveConfigHidrawPath(devicePath, &wired);
    if (hidraw.isEmpty())
        return false;

    int fd = ::open(hidraw.toUtf8().constData(), O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        fd = ::open(hidraw.toUtf8().constData(), O_RDONLY | O_NONBLOCK);
        if (fd < 0)
            return false;
    }

    m_devicePath = devicePath;
    m_hidrawPath = hidraw;
    m_fd         = fd;
    m_isWired    = wired;

    m_readNotifier = new QSocketNotifier(m_fd, QSocketNotifier::Read, this);
    connect(m_readNotifier, &QSocketNotifier::activated,
            this, &AttackSharkDevice::onHidrawReadyRead);

    if (m_isWired) {
        // In Wired USB mode, the mouse is charging via cable
        m_lastBattery.isCharging = true;
        emit batteryStatusChanged(m_lastBattery);
    } else {
        m_lastBattery.isCharging = false;
        emit batteryStatusChanged(m_lastBattery);
    }

    emit connectionModeChanged(m_isWired, m_hidrawPath);

    // Drain any buffered reports immediately
    onHidrawReadyRead();
    return true;
}

void AttackSharkDevice::closeDevice()
{
    if (m_readNotifier) {
        m_readNotifier->setEnabled(false);
        m_readNotifier->deleteLater();
        m_readNotifier = nullptr;
    }
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
    m_hidrawPath.clear();
    m_isWired = false;
}

void AttackSharkDevice::checkHotplugTransition()
{
    bool preferredWired = false;
    const QString preferredHidraw = resolveConfigHidrawPath(m_devicePath, &preferredWired);

    if (preferredHidraw.isEmpty()) {
        if (m_fd >= 0) {
            closeDevice();
            emit deviceDisconnected();
        }
        return;
    }

    // Automatically switch between Wired Charging mode (1d57:fa61) and 2.4G Wireless mode (1d57:fa60)
    // when the user plugs in or unplugs the USB cable
    if (m_fd < 0 || preferredHidraw != m_hidrawPath || preferredWired != m_isWired) {
        const QString savedPath = m_devicePath;
        openDevice(savedPath);
    }
}

void AttackSharkDevice::onHidrawReadyRead()
{
    if (m_fd < 0)
        return;

    uint8_t buf[64];
    while (true) {
        const ssize_t n = ::read(m_fd, buf, sizeof(buf));
        if (n > 0) {
            parseIncomingReport(buf, n);
        } else {
            if (n < 0 && (errno == ENODEV || errno == EIO || errno == EBADF)) {
                closeDevice();
                emit deviceDisconnected();
            }
            break;
        }
    }
}

void AttackSharkDevice::parseIncomingReport(const uint8_t *buf, ssize_t length)
{
    // Attack Shark X11 wireless packet handling on Interface 2:
    // 1. DPI Stage Switch Notification from physical mouse button:
    // Signature: [0x03, 0x10, 0x10, <stage 1-based>, 0x00]
    if (length >= 4 && buf[0] == 0x03 && buf[1] == 0x10 && buf[2] == 0x10) {
        int stage1Based = static_cast<int>(buf[3]);
        if (stage1Based == 0 && length >= 5) {
            stage1Based = static_cast<int>(buf[4]);
        }
        if (stage1Based >= 1 && stage1Based <= kDpiStagesCount) {
            emit activeDpiStageChanged(stage1Based - 1);
        }
    }

    // 2. Battery & Charging status telemetry report:
    // - Beken 10-step firmware:  [0x03, 0x10, 0x40, <state>, <level 1..10 (0x01..0x0a = 10%..100%)>]
    // - Standard 100-step fw:    [0x03, 0x55, 0x40, <state>, <percentage 0..100 (0x00..0x64)>]
    if (length >= 5 && buf[0] == 0x03 && buf[2] == 0x40 && (buf[1] == 0x10 || buf[1] == 0x55)) {
        const uint8_t state = buf[3];
        const int raw = static_cast<int>(buf[4]);
        int pct = raw;
        if (buf[1] == 0x10 && raw <= 10) {
            pct = raw * 10;
        }
        pct = std::clamp(pct, 0, 100);

        // State: 0x02 = Charging, 0x03 = Fully charged, 0x01 = Discharging
        const bool charging = m_isWired || (state == 0x02);

        if (m_lastBattery.percentage != pct || m_lastBattery.isCharging != charging) {
            m_lastBattery.percentage = pct;
            m_lastBattery.isCharging = charging;
            emit batteryStatusChanged(m_lastBattery);
        }
    }
}

BatteryStatus AttackSharkDevice::pollBatteryOnce(int timeoutMs)
{
    // Check if wired/wireless mode changed first
    checkHotplugTransition();

    if (m_fd < 0)
        return m_lastBattery;

    onHidrawReadyRead();
    if (m_isWired) {
        m_lastBattery.isCharging = true;
        return m_lastBattery;
    }

    if (m_lastBattery.percentage >= 0)
        return m_lastBattery;

    struct pollfd pfd {};
    pfd.fd     = m_fd;
    pfd.events = POLLIN;

    const int rc = ::poll(&pfd, 1, timeoutMs);
    if (rc > 0 && (pfd.revents & POLLIN)) {
        onHidrawReadyRead();
    }

    return m_lastBattery;
}

bool AttackSharkDevice::sendFeatureReport(const uint8_t *data, size_t length, QString *errorMessage)
{
    // Ensure we are targeting the active interface (e.g. Wired if plugged in via USB)
    checkHotplugTransition();

    int targetFd = m_fd;
    bool tempOpened = false;

    if (targetFd < 0) {
        const QString hidraw = m_hidrawPath.isEmpty()
            ? resolveConfigHidrawPath(m_devicePath)
            : m_hidrawPath;
        if (hidraw.isEmpty()) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Attack Shark X11 configuration interface not found.");
            return false;
        }
        targetFd = ::open(hidraw.toUtf8().constData(), O_RDWR | O_NONBLOCK);
        if (targetFd < 0) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Cannot open %1: %2").arg(hidraw, QString::fromLocal8Bit(std::strerror(errno)));
            return false;
        }
        tempOpened = true;
    }

    std::array<uint8_t, 64> buffer {};
    const size_t copyLen = std::min(length, buffer.size());
    std::memcpy(buffer.data(), data, copyLen);

    const int rc = ::ioctl(targetFd, HIDIOCSFEATURE(copyLen), buffer.data());
    const int savedErrno = errno;

    if (tempOpened)
        ::close(targetFd);

    if (rc < 0) {
        if (errorMessage)
            *errorMessage = QStringLiteral("HIDIOCSFEATURE failed: %1").arg(QString::fromLocal8Bit(std::strerror(savedErrno)));
        return false;
    }

    return true;
}

void AttackSharkDevice::buildPollingReport(PollingRate rate, uint8_t out[9])
{
    const int idx = std::clamp(static_cast<int>(rate), 0, 3);
    const uint8_t report[9] = {
        0x06, 0x09, 0x01,
        kPollingRatePayloads[idx][0],
        kPollingRatePayloads[idx][1],
        0x00, 0x00, 0x00, 0x00
    };
    std::memcpy(out, report, sizeof(report));
}

void AttackSharkDevice::buildColorAndPowerReport(const MouseConfig &config, uint8_t out[15])
{
    const int modeIdx = std::clamp(static_cast<int>(config.colorMode), 0, 3);
    std::memcpy(out, kBaseColorModes[modeIdx], 15);

    const int sleepTime     = std::clamp(config.sleepTimeMin, 1, 30);
    const int deepSleepTime = std::clamp(config.deepSleepTimeMin, 1, 60);
    const int keyRespTime   = std::clamp(config.keyResponseTimeMs, 4, 50);

    uint8_t hardwareSpeed = out[4] & 0x0F;
    if (hardwareSpeed == 0)
        hardwareSpeed = 0x01;

    const int bucket = (deepSleepTime - 1) / 16;
    out[4]  = static_cast<uint8_t>((bucket << 4) | hardwareSpeed);
    out[5]  = static_cast<uint8_t>(0x08 + (deepSleepTime * 0x10));
    out[9]  = static_cast<uint8_t>(sleepTime * 2);
    out[10] = static_cast<uint8_t>(((keyRespTime - 4) / 2) + 2);

    // Checksum is the 8-bit sum of bytes 3..10 inclusive (per UserPreferencesBuilder specification)
    uint8_t checksum = 0;
    for (int i = 3; i <= 10; ++i) {
        checksum = static_cast<uint8_t>(checksum + out[i]);
    }
    out[12] = checksum;
}

void AttackSharkDevice::buildDpiAndSensorReport(const MouseConfig &config, uint8_t out[56])
{
    const uint8_t activeStage1Based = static_cast<uint8_t>(
        std::clamp(config.activeDpiStage + 1, 1, kDpiStagesCount));

    // Compute Stage Mask (> 12000 DPI) for stages 1..5 + stage 6 (default 22000 DPI = bit 5)
    uint8_t stageMask = 0x20; // bit 5 set for stage 6 (22000 DPI)
    for (int i = 0; i < kDpiStagesCount; ++i) {
        if (config.dpiStages[i].needsStageMask()) {
            stageMask |= static_cast<uint8_t>(1u << i);
        }
    }

    const uint8_t report[56] = {
        0x04, 0x38, 0x01,                                                     // Bytes 0..2: Header
        config.angleSnap ? uint8_t(0x01) : uint8_t(0x00),                     // Byte 3: Angle Snap
        config.rippleControl ? uint8_t(0x01) : uint8_t(0x00),                 // Byte 4: Ripple Control
        0x1f,                                                                 // Byte 5: Enable bitmask for 5 stages (0b00011111)
        stageMask,                                                            // Byte 6: Stage Mask A (DPI > 12000)
        stageMask,                                                            // Byte 7: Stage Mask B (duplicate)
        config.dpiStages[0].toHardwareIndex(),                                // Byte 8:  Stage 1 encoded DPI
        config.dpiStages[1].toHardwareIndex(),                                // Byte 9:  Stage 2 encoded DPI
        config.dpiStages[2].toHardwareIndex(),                                // Byte 10: Stage 3 encoded DPI
        config.dpiStages[3].toHardwareIndex(),                                // Byte 11: Stage 4 encoded DPI
        config.dpiStages[4].toHardwareIndex(),                                // Byte 12: Stage 5 encoded DPI
        0x81,                                                                 // Byte 13: Stage 6 encoded DPI (22000 default)
        0x00, 0x00,                                                           // Bytes 14..15: Fixed
        config.dpiStages[0].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 16: High Flag 1
        config.dpiStages[1].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 17: High Flag 2
        config.dpiStages[2].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 18: High Flag 3
        config.dpiStages[3].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 19: High Flag 4
        config.dpiStages[4].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 20: High Flag 5
        0x01,                                                                 // Byte 21: High Flag 6 (22000 DPI)
        0x00, 0x00,                                                           // Bytes 22..23: Fixed
        activeStage1Based,                                                    // Byte 24: Active DPI Stage (1..5)
        // Bytes 25..49: Fixed RGB / profile data required by Attack Shark X11 firmware
        0xff, 0x00, 0x00, 0x00,
        0xff, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0x00, 0x00,
        0xff, 0xff, 0xff, 0x00,
        0xff, 0xff, 0x40, 0x00,
        0xff, 0xff, 0xff, 0x02,
        0x00, 0x00,                                                           // Bytes 50..51: 16-bit BE Checksum placeholder
        0x00, 0x00, 0x00, 0x00                                                // Bytes 52..55: Padding
    };

    std::memcpy(out, report, sizeof(report));

    // Calculate 16-bit Big-Endian checksum over bytes 3..49 inclusive
    uint16_t checksum = 0;
    for (int i = 3; i <= 49; ++i) {
        checksum = static_cast<uint16_t>(checksum + out[i]);
    }
    out[50] = static_cast<uint8_t>((checksum >> 8) & 0xFF);
    out[51] = static_cast<uint8_t>(checksum & 0xFF);
}

bool AttackSharkDevice::applyConfiguration(const MouseConfig &config, QString *errorMessage)
{
    if (!config.isValid()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Invalid mouse configuration parameters.");
        return false;
    }

    uint8_t pollingReport[9];
    buildPollingReport(config.pollingRate, pollingReport);
    if (!sendFeatureReport(pollingReport, sizeof(pollingReport), errorMessage))
        return false;

    QThread::msleep(kInterReportDelayMs);

    uint8_t colorReport[15];
    buildColorAndPowerReport(config, colorReport);
    if (!sendFeatureReport(colorReport, sizeof(colorReport), errorMessage))
        return false;

    QThread::msleep(kInterReportDelayMs);

    uint8_t dpiReport[56];
    buildDpiAndSensorReport(config, dpiReport);
    if (!sendFeatureReport(dpiReport, sizeof(dpiReport), errorMessage))
        return false;

    // Drain ACK reports
    onHidrawReadyRead();
    return true;
}

} // namespace attackshark
