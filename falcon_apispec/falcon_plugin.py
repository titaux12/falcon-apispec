import copy
import logging
import re
from typing import Dict, Any

from apispec import BasePlugin, yaml_utils
from apispec.exceptions import APISpecError

log = logging.getLogger(__name__)

# Typing
Resource = object


class FalconPlugin(BasePlugin):
    """APISpec plugin for Falcon"""

    def __init__(self, app, cache_enabled: bool = False):
        super(FalconPlugin, self).__init__()
        self._app = app
        self._cache_enabled = cache_enabled
        log.debug(f"cache_enabled={cache_enabled} for the parsing of the falcon's router")
        self._mapping_cached = None

    def _get_resource_uri_mapping(self) -> Dict[Resource, Dict[str, Any]]:
        if self._cache_enabled and self._mapping_cached:
            return self._mapping_cached
        log.info("Processing the falcon's router's tree")
        nodes = copy.copy(self._app._router._roots)  # noqa using the internal implementation of falcon

        mapping = dict()
        for node in nodes:
            log.debug(f"Processing node={node}")  # TODO remove me
            if _node_without_resource(node):
                log.debug(f"Reached a node without any resource associated to it, adding its children to the processing queue")
                nodes.extend(node.children)
                continue
            else:
                uri = node.uri_template
                resource = node.resource
                method_map = node.method_map
                nodes.extend(node.children)
            log.debug(f"Found URI='{uri}' to process")
            # FIXME Resources can have several uri and methods - this is not good.
            mapping[resource] = {
                "uri": uri,
                "methods": dict()
            }
            if method_map:
                for http_method, python_method in method_map.items():
                    if python_method.__dict__.get("__module__") == "falcon.responders":
                        # Skipping the built-in method of falcon
                        continue
                    mapping[resource]["methods"][http_method.lower()] = python_method

            # nodes is a list of tree, so it needs to be flatten to be parsed in one `for` loop
            nodes.extend(node.children)
        self._mapping_cached = mapping
        return self._mapping_cached

    def path_helper(self, operations, resource, base_path=None, **kwargs):  # noqa the signature does not match as custom kwargs are used
        """Path helper that allows passing a Falcon resource instance."""
        resource_uri_mapping = self._get_resource_uri_mapping()

        if resource not in resource_uri_mapping:
            raise APISpecError(f"Could not find endpoint for resource {resource}")

        operations.update(yaml_utils.load_operations_from_docstring(resource.__doc__) or {})
        path = resource_uri_mapping[resource]["uri"]

        if base_path is not None:
            # make sure base_path accept either with or without leading slash
            # swagger 2 usually come with leading slash but not in openapi 3.x.x
            base_path = '/' + base_path.strip('/')
            path = re.sub(base_path, "", path, 1)

        methods = resource_uri_mapping[resource]["methods"]

        for method_name, method_handler in methods.items():
            docstring_yaml = yaml_utils.load_yaml_from_docstring(method_handler.__doc__)
            operations[method_name] = docstring_yaml or dict()
        return path


def _node_without_resource(node) -> bool:
    """Return if the falcon router's node is representing a valid falcon route"""
    # The 3 conditions seems to be overkilled because of the falcon's implementation:
    #  the assignation of these 3 attributes are tangled together in the trees construction
    return node.method_map is not None and node.uri_template is not None and node.resource is not None
