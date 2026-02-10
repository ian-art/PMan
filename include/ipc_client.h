/*
 * This file is part of Priority Manager (PMan).
 *
 * Copyright (c) 2025 Ian Anthony R. Tancinco
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef PMAN_IPC_CLIENT_H
#define PMAN_IPC_CLIENT_H

#include <nlohmann/json.hpp>
#include <string>

class IpcClient {
public:
    struct Response {
        bool success;
        std::string message;
        bool denied; // True if action was blocked by security policy
    };

    /**
     * Sends a configuration update payload to the PMan Service.
     * Automatically wraps the data in a SET_CONFIG command envelope.
     * * @param configData The partial or full configuration JSON object.
     * @return Response containing the service's verdict.
     */
    static Response SendConfig(const nlohmann::json& configData);
};

#endif // PMAN_IPC_CLIENT_H
