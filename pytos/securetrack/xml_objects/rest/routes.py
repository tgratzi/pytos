# Copyright 2017 Tufin Technologies Security Suite. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging

from pytos.common.base_types import XML_Object_Base, XML_List
from pytos.common.definitions import xml_tags
from pytos.common.functions import get_xml_text_value
from pytos.common.logging.definitions import XML_LOGGER_NAME

logger = logging.getLogger(XML_LOGGER_NAME)


class Route(XML_Object_Base):
    def __init__(self, network_ip, network_mask, next_hop_ip, interface=None):
        self.network_ip = network_ip
        self.network_mask = network_mask
        self.next_hop_ip = next_hop_ip
        self.interface = interface
        super().__init__(xml_tags.Elements.ROUTE)

    @classmethod
    def from_xml_node(cls, xml_node):
        network_ip = get_xml_text_value(xml_node, xml_tags.Elements.NETWORK_IP)
        network_mask = get_xml_text_value(xml_node, xml_tags.Elements.NETWORK_MASK)
        next_hop_ip = get_xml_text_value(xml_node, xml_tags.Elements.NEXT_HOP_IP)
        interface = get_xml_text_value(xml_node, xml_tags.Elements.INTERFACE)
        return cls(network_ip, network_mask, next_hop_ip, interface)

    def __str__(self):
        return "Route({},{},{},{})".format(self.network_ip, self.network_mask, self.next_hop_ip, self.interface)


class RoutesList(XML_List):
    """
    :type routes: list[Route]
    """

    def __init__(self, routes):
        self.routes = routes
        super().__init__(xml_tags.Elements.ROUTES, routes)

    @classmethod
    def from_xml_node(cls, xml_node):
        routes = []
        for route_node in xml_node.iter(tag=xml_tags.Elements.ROUTE):
            routes.append(Route.from_xml_node(route_node))
        return cls(routes)
