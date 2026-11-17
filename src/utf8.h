#pragma once

#include <cstddef>
#include <string_view>

namespace huxerui::localnetwork::detail {

/// Validates UTF-8 text suitable for system APIs that use null-terminated strings.
inline bool ValidUtf8Text(std::string_view text) {
  for (std::size_t i = 0; i < text.size();) {
    const auto first = static_cast<unsigned char>(text[i++]);
    if (first == 0) return false;
    if (first < 0x80) continue;
    if (first < 0xC2 || first > 0xF4) return false;
    const std::size_t trailing = first < 0xE0 ? 1 : first < 0xF0 ? 2 : 3;
    if (text.size() - i < trailing) return false;
    const auto next = static_cast<unsigned char>(text[i]);
    if ((first == 0xE0 && next < 0xA0) || (first == 0xED && next >= 0xA0) ||
        (first == 0xF0 && next < 0x90) || (first == 0xF4 && next >= 0x90)) return false;
    for (std::size_t j = 0; j < trailing; ++j) {
      if ((static_cast<unsigned char>(text[i++]) & 0xC0) != 0x80) return false;
    }
  }
  return true;
}

} // namespace huxerui::localnetwork::detail
