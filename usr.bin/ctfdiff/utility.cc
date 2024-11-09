#include "ctftype.hpp"
#include "utility.hpp"
#include <cstdint>
#include <typeinfo>

int flags = 0;
std::vector<const std::type_info *> ignore_ids = { &typeid(CtfTypeTypeDef) };
