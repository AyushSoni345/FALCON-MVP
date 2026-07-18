import uuid
from datetime import datetime
from typing import List
from module4.app.models.models import SecurityGraphEvent
from module4.app.exceptions.exceptions import InvalidSecurityGraphEventException

class SecurityGraphEventValidator:
    """
    Dedicated validation pipeline for validating incoming SecurityGraphEvent objects
    from Module 3 prior to AI reasoning processing.
    """

    @classmethod
    def validate_event(cls, event: SecurityGraphEvent) -> None:
        """
        Runs the full validation pipeline on a SecurityGraphEvent.
        Raises InvalidSecurityGraphEventException if any validation check fails.
        """
        cls.validate_event_context(event)
        cls.validate_nodes_and_relationships(event)
        cls.validate_paths(event)
        cls.validate_metrics_and_context(event)
        cls.validate_state_metadata(event)

    @classmethod
    def validate_event_context(cls, event: SecurityGraphEvent) -> None:
        context = event.event_context
        
        # Verify event_uuid is a valid UUID
        try:
            uuid.UUID(context.event_uuid)
        except ValueError:
            raise InvalidSecurityGraphEventException(
                f"event_uuid '{context.event_uuid}' is not a valid UUID format."
            )
            
        # Verify normalized_timestamp is a valid datetime
        if not isinstance(context.normalized_timestamp, datetime):
            raise InvalidSecurityGraphEventException(
                "normalized_timestamp must be a valid datetime object."
            )
            
        # Verify other required fields
        if not context.correlation_id or not context.correlation_id.strip():
            raise InvalidSecurityGraphEventException("correlation_id cannot be empty.")
        if not context.event_type or not context.event_type.strip():
            raise InvalidSecurityGraphEventException("event_type cannot be empty.")
        if not context.source_system or not context.source_system.strip():
            raise InvalidSecurityGraphEventException("source_system cannot be empty.")

    @classmethod
    def validate_nodes_and_relationships(cls, event: SecurityGraphEvent) -> None:
        # Create a set of existing node IDs
        existing_nodes = {node.node_id for node in event.graph_nodes}
        
        # Validate that all nodes have non-empty IDs and types
        for node in event.graph_nodes:
            if not node.node_id or not node.node_id.strip():
                raise InvalidSecurityGraphEventException("GraphNode ID cannot be empty.")
            if not node.node_type or not node.node_type.strip():
                raise InvalidSecurityGraphEventException(
                    f"GraphNode '{node.node_id}' must have a valid node_type."
                )

        # Validate relationships
        relationship_ids = set()
        for rel in event.graph_relationships:
            if not rel.relationship_id or not rel.relationship_id.strip():
                raise InvalidSecurityGraphEventException("GraphRelationship ID cannot be empty.")
            if rel.relationship_id in relationship_ids:
                raise InvalidSecurityGraphEventException(
                    f"Duplicate relationship ID detected: '{rel.relationship_id}'"
                )
            relationship_ids.add(rel.relationship_id)
            
            # Verify source and target nodes exist in the nodes set
            if rel.source_node not in existing_nodes:
                raise InvalidSecurityGraphEventException(
                    f"Relationship '{rel.relationship_id}' references non-existent source node '{rel.source_node}'."
                )
            if rel.target_node not in existing_nodes:
                raise InvalidSecurityGraphEventException(
                    f"Relationship '{rel.relationship_id}' references non-existent target node '{rel.target_node}'."
                )
            
            # Verify basic fields
            if not rel.relationship_type or not rel.relationship_type.strip():
                raise InvalidSecurityGraphEventException(
                    f"Relationship '{rel.relationship_id}' must have a valid relationship_type."
                )
            if not isinstance(rel.timestamp, datetime):
                raise InvalidSecurityGraphEventException(
                    f"Relationship '{rel.relationship_id}' timestamp must be a datetime object."
                )
            if not (0.0 <= rel.confidence <= 1.0):
                raise InvalidSecurityGraphEventException(
                    f"Relationship '{rel.relationship_id}' confidence '{rel.confidence}' must be between 0.0 and 1.0."
                )

    @classmethod
    def validate_paths(cls, event: SecurityGraphEvent) -> None:
        existing_nodes = {node.node_id for node in event.graph_nodes}
        path_ids = set()
        
        for path in event.graph_paths:
            if not path.path_id or not path.path_id.strip():
                raise InvalidSecurityGraphEventException("GraphPath ID cannot be empty.")
            if path.path_id in path_ids:
                raise InvalidSecurityGraphEventException(
                    f"Duplicate path ID detected: '{path.path_id}'"
                )
            path_ids.add(path.path_id)
            
            if not path.path_nodes:
                raise InvalidSecurityGraphEventException(
                    f"Path '{path.path_id}' must contain at least one node."
                )
                
            # Verify all nodes in path exist
            for node_id in path.path_nodes:
                if node_id not in existing_nodes:
                    raise InvalidSecurityGraphEventException(
                        f"Path '{path.path_id}' references non-existent node '{node_id}'."
                    )
            
            # Verify path length matches nodes count
            # A path with N nodes should have path_length = N - 1 (edges) or N depending on implementation
            # We will verify that path_nodes has at least 1 element, and path_length is non-negative
            if path.path_length < 0:
                raise InvalidSecurityGraphEventException(
                    f"Path '{path.path_id}' length '{path.path_length}' cannot be negative."
                )

    @classmethod
    def validate_metrics_and_context(cls, event: SecurityGraphEvent) -> None:
        metrics = event.graph_metrics
        if metrics.relationship_count < 0:
            raise InvalidSecurityGraphEventException(
                f"relationship_count '{metrics.relationship_count}' cannot be negative."
            )
        if metrics.graph_depth < 0:
            raise InvalidSecurityGraphEventException(
                f"graph_depth '{metrics.graph_depth}' cannot be negative."
            )
            
        context = event.graph_context
        if not context.primary_entity or not context.primary_entity.strip():
            raise InvalidSecurityGraphEventException("graph_context primary_entity cannot be empty.")

    @classmethod
    def validate_state_metadata(cls, event: SecurityGraphEvent) -> None:
        metadata = event.graph_state_metadata
        if not metadata.graph_version or not metadata.graph_version.strip():
            raise InvalidSecurityGraphEventException("graph_version cannot be empty.")
        if not isinstance(metadata.graph_timestamp, datetime):
            raise InvalidSecurityGraphEventException("graph_timestamp must be a datetime object.")
