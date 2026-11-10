#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace frego::catalog {

// Text invariant (DESIGN §4.1, M7): every string in a catalog event is valid UTF-8.
// Use this whenever device-supplied bytes become an event string. It replaces invalid
// sequences with U+FFFD, strips control characters except tab, and truncates at a
// code-point boundary so the result is at most max_len bytes.
std::string text(std::string_view bytes, std::size_t max_len = 255);

}  // namespace frego::catalog
