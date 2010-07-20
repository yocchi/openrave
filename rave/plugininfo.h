// Copyright (C) 2006-2009 Rosen Diankov (rdiankov@cs.cmu.edu)
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
/** \file plugininfo.h
    \brief  Holds the plugin information structure.
 */
#ifndef OPENRAVE_PLUGIN_INFO
#define OPENRAVE_PLUGIN_INFO

namespace OpenRAVE {

/** \brief Holds all the %OpenRAVE-specific information provided by a plugin.
    
    \ingroup plugin_exports
    PLUGININFO has a hash computed for it to validate its size and type before having a plugin fill it.
*/
struct PLUGININFO
{
    std::map<InterfaceType, std::vector<std::string> > interfacenames;
};

}

#endif