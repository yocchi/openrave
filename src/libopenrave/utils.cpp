// -*- coding: utf-8 -*-
// Copyright (C) 2006-2012 Rosen Diankov <rosen.diankov@gmail.com>
//
// This file is part of OpenRAVE.
// OpenRAVE is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#include "libopenrave.h"
#include <openrave/utils.h>

#include "md5.h"

namespace OpenRAVE {

#define DefineRavePrintfW(LEVEL) \
     int RavePrintfW ## LEVEL(const log4cxx::LoggerPtr& logger, const log4cxx::spi::LocationInfo& location, const wchar_t *wfmt, ...) \
    { \
        va_list list; \
        wchar_t wbuf[512]; /* wide char buffer to hold vswprintf result */ \
        wchar_t* ws = &wbuf[0]; \
        wchar_t* wsallocated = NULL; /* allocated wide char buffer */ \
        int wslen = sizeof(wbuf)/sizeof(wchar_t); /* wide char buffer length (character count) */ \
        int wr = -1; \
        \
        va_start(list, wfmt); \
        for (;;) { \
            wr = vswprintf(ws, wslen, wfmt, list); \
            if (wr >= 0) { \
                break; \
            } \
            if (wslen >= 16384) { \
                wr = -1; \
                break; \
            } \
            /* vswprintf does not tell us how much space is needed, so we need to grow until it is satisfied */ \
            wslen *= 2; \
            wsallocated = (wchar_t*)realloc(wsallocated, wslen*sizeof(wchar_t)); \
            ws = wsallocated; \
        } \
        if (wr >= 0) { \
            /* get rid of the trailing \n if presnet */ \
            if (wr > 0 && ws[wr-1] == L'\n') { \
                ws[wr-1] = '\0'; \
            } \
            if (!!logger) { \
                OPENRAVE_LOG4CXX ## LEVEL(logger, ws, location); \
            } else { \
                wprintf(L"%ls\n", ws); \
            } \
        } \
        va_end(list); \
        if (wsallocated != NULL) { \
            free(wsallocated); \
            wsallocated = NULL; \
        } \
        return wr; \
    }

    DefineRavePrintfW(_INFOLEVEL)
    DefineRavePrintfW(_FATALLEVEL)
    DefineRavePrintfW(_ERRORLEVEL)
    DefineRavePrintfW(_WARNLEVEL)
//DefineRavePrintfW(_INFOLEVEL)
    DefineRavePrintfW(_DEBUGLEVEL)
    DefineRavePrintfW(_VERBOSELEVEL)

#define DefineRavePrintfA(LEVEL) \
     int RavePrintfA ## LEVEL(const log4cxx::LoggerPtr& logger, const log4cxx::spi::LocationInfo& location, const std::string& s) \
    { \
        if (!!logger) { \
            if (s.size() > 0 && s[s.size()-1] == '\n') { \
                std::string s1(s, 0, s.size()-1); \
                OPENRAVE_LOG4CXX ## LEVEL(logger, s1, location); \
            } else { \
                OPENRAVE_LOG4CXX ## LEVEL(logger, s, location); \
            } \
        } else { \
            if (s.size() > 0 && s[s.size()-1] == '\n') { \
                printf("%s", s.c_str()); \
            } else { \
                printf("%s\n", s.c_str()); \
            } \
        } \
        return s.size(); \
    } \
    \
     int RavePrintfA ## LEVEL(const log4cxx::LoggerPtr& logger, const log4cxx::spi::LocationInfo& location, const char *fmt, ...) \
    { \
        va_list list; \
        char buf[512]; \
        char* s = &buf[0]; \
        char* sallocated = NULL; \
        int slen = 0; \
        int r = 0; \
        va_start(list,fmt); \
        r = vsnprintf(buf, sizeof(buf)/sizeof(char), fmt, list); \
        if (r >= (int)(sizeof(buf)/sizeof(char))) { \
            slen = r+1; \
            sallocated = (char*)malloc(slen*sizeof(char)); \
            s = sallocated; \
            r = vsnprintf(s, r+1, fmt, list); \
            if (r >= slen) { \
                r = -1; \
            } \
        } \
        if (r >= 0) { \
            /* get rid of the trailing \n if presnet */ \
            if (r > 0 && s[r-1] == '\n') { \
                s[r-1] = '\0'; \
            } \
            if (!!logger) { \
                OPENRAVE_LOG4CXX ## LEVEL(logger, s, location); \
            } else { \
                printf("%s\n", s); \
            } \
        } \
        va_end(list); \
        if (sallocated != NULL) { \
            free(sallocated); \
            sallocated = NULL; \
        } \
        return r; \
    }

        DefineRavePrintfA(_INFOLEVEL)

        DefineRavePrintfA(_FATALLEVEL)

        DefineRavePrintfA(_ERRORLEVEL)

        DefineRavePrintfA(_WARNLEVEL)
//DefineRavePrintfA(_INFOLEVEL)
        DefineRavePrintfA(_DEBUGLEVEL)

        DefineRavePrintfA(_VERBOSELEVEL)

    namespace utils {

std::string GetMD5HashString(const std::string& s)
{
    if( s.size() == 0 )
        return "";

    md5_state_t state;
    md5_byte_t digest[16];

    md5_init(&state);
    md5_append(&state, (const md5_byte_t *)s.c_str(), s.size());
    md5_finish(&state, digest);
    string hex_output;
    hex_output.resize(32);
    for (int di = 0; di < 16; ++di) {
        int n = (digest[di]&0xf);
        hex_output[2*di+1] = n > 9 ? ('a'+n-10) : ('0'+n);
        n = (digest[di]&0xf0)>>4;
        hex_output[2*di+0] = n > 9 ? ('a'+n-10) : ('0'+n);
    }
    return hex_output;
}

std::string GetMD5HashString(const std::vector<uint8_t>&v)
{
    if( v.size() == 0 )
        return "";

    md5_state_t state;
    md5_byte_t digest[16];

    md5_init(&state);
    md5_append(&state, (const md5_byte_t *)&v[0], v.size());
    md5_finish(&state, digest);
    string hex_output;
    hex_output.resize(32);
    for (int di = 0; di < 16; ++di) {
        int n = (digest[di]&0xf);
        hex_output[2*di+0] = n > 9 ? ('a'+n-10) : ('0'+n);
        n = (digest[di]&0xf0)>>4;
        hex_output[2*di+1] = n > 9 ? ('a'+n-10) : ('0'+n);
    }
    return hex_output;
}

bool PairStringLengthCompare(const std::pair<std::string, std::string>&p0, const std::pair<std::string, std::string>&p1)
{
    return p0.first.size() > p1.first.size();
}

std::string& SearchAndReplace(std::string& out, const std::string& in, const std::vector< std::pair<std::string, std::string> >&_pairs)
{
    BOOST_ASSERT(&out != &in);
    FOREACHC(itp,_pairs) {
        BOOST_ASSERT(itp->first.size()>0);
    }
    std::vector< std::pair<std::string, std::string> > pairs = _pairs;
    stable_sort(pairs.begin(),pairs.end(),PairStringLengthCompare);
    out.resize(0);
    size_t startindex = 0;
    while(startindex < in.size()) {
        size_t nextindex=std::string::npos;
        std::vector< std::pair<std::string, std::string> >::const_iterator itbestp;
        FOREACHC(itp,pairs) {
            size_t index = in.find(itp->first,startindex);
            if((nextindex == std::string::npos)|| ((index != std::string::npos)&&(index < nextindex)) ) {
                nextindex = index;
                itbestp = itp;
            }
        }
        if( nextindex == std::string::npos ) {
            out += in.substr(startindex);
            break;
        }
        out += in.substr(startindex,nextindex-startindex);
        out += itbestp->second;
        startindex = nextindex+itbestp->first.size();
    }
    return out;
}

std::string GetFilenameUntilSeparator(std::istream& sinput, char separator)
{
    std::string filename;
    if( !getline(sinput, filename, separator) ) {
        // just input directly
        sinput >> filename;
    }

    // trim leading spaces
    std::size_t startpos = filename.find_first_not_of(" \t");
    std::size_t endpos = filename.find_last_not_of(" \t");

    // if all spaces or empty return an empty string
    if( string::npos == startpos || string::npos == endpos ) {
        return "";
    }
    return filename.substr( startpos, endpos-startpos+1 );
}

} // utils
} // OpenRAVE
