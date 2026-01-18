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

#ifndef VERSION_H
#define VERSION_H

#define PMAN_VERSION_MAJOR 3
#define PMAN_VERSION_MINOR 4
#define PMAN_VERSION_PATCH 0
#define PMAN_VERSION_BUILD 2026

// Helper macros to turn numbers into strings
#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#define PMAN_FVERSION_STRING STRINGIZE(PMAN_VERSION_MAJOR) "." \
                            STRINGIZE(PMAN_VERSION_MINOR) "." \
                            STRINGIZE(PMAN_VERSION_PATCH)
#define PMAN_PVERSION_STRING STRINGIZE(PMAN_VERSION_MAJOR) "."

#define PMAN_FILE_VERSION_STRING PMAN_FVERSION_STRING "." STRINGIZE(PMAN_VERSION_BUILD)
#define PMAN_PRODUCT_VERSION_STRING PMAN_PVERSION_STRING STRINGIZE(PMAN_VERSION_BUILD)
#endif // VERSION_H
