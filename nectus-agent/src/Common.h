/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains declaration of common values used in various parts of code

#pragma once

const int CACHED_DATA_VALIDITY_PERIOD_SEC = 60;
constexpr uint32_t MEGABYTE_SIZE = 1024 * 1024;
constexpr uint32_t GIGABYTE_SIZE = 1024 * 1024 * 1024;

using ByteVector = std::vector<uint8_t>;
