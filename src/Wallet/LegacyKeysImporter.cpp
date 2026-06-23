// Legacy key-file import is not supported on the post-quantum Discrete wallet.
// This file is retained as a stub so that stale #include sites compile.

#include "LegacyKeysImporter.h"
#include <stdexcept>

namespace CryptoNote {

void importLegacyKeys(const std::string&, const std::string&, std::ostream&) {
  throw std::runtime_error("Legacy key-file import is not supported");
}

}
