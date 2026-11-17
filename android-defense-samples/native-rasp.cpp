/**
 * Educational Native RASP (Runtime Application Self-Protection) Reference
 *
 * Demonstrates basic Linux/Android process self-inspection techniques:
 * 1. Checking /proc/self/status for TracerPid != 0 (ptrace debugger detection).
 * 2. Scanning /proc/self/maps for unexpected injected shared libraries.
 *
 * NOTE: Determined attackers on rooted devices can bypass client-side checks.
 * Always enforce purchase & offer eligibility on your trusted backend.
 */

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace security {

bool is_tracer_attached() {
    std::ifstream status_file("/proc/self/status");
    if (!status_file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(status_file, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::istringstream iss(line.substr(10));
            int tracer_pid = 0;
            iss >> tracer_pid;
            return tracer_pid != 0;
        }
    }
    return false;
}

bool has_suspicious_memory_mapping() {
    std::ifstream maps_file("/proc/self/maps");
    if (!maps_file.is_open()) {
        return false;
    }

    const std::vector<std::string> suspicious_markers = {
        "frida",
        "gum-js-loop",
        "xposed",
        "substrate"
    };

    std::string line;
    while (std::getline(maps_file, line)) {
        for (const auto& marker : suspicious_markers) {
            if (line.find(marker) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace security
