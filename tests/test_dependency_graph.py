"""Unit tests for Autonomous API Dependency Graph & Stateful Workflow Synthesizer."""

import pytest
from core.dependency_graph import ApiDependencyGraph


SAMPLE_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test CRUD Shop API", "version": "1.0.0"},
    "paths": {
        "/users": {
            "post": {
                "summary": "Create User Account",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "email": {"type": "string", "format": "email"},
                                },
                            }
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "Created",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "string", "format": "uuid"},
                                        "username": {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/users/{id}": {
            "get": {
                "summary": "Get User Profile",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
                ],
                "responses": {"200": {"description": "OK"}},
            },
            "delete": {
                "summary": "Delete User Account",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
                ],
                "responses": {"204": {"description": "Deleted"}},
            },
        },
    },
}


def test_dependency_graph_analysis():
    graph = ApiDependencyGraph(SAMPLE_OPENAPI_SPEC)
    assert len(graph.producers) == 1
    assert graph.producers[0].endpoint == "/users"
    assert "id" in graph.producers[0].produced_fields

    assert len(graph.consumers) == 2
    assert any(c.endpoint == "/users/{id}" and c.method == "GET" for c in graph.consumers)


def test_workflow_synthesis():
    graph = ApiDependencyGraph(SAMPLE_OPENAPI_SPEC)
    workflows = graph.synthesize_workflows(max_workflows=2)

    assert len(workflows) > 0
    wf = workflows[0]
    assert len(wf.steps) == 3

    # Step 1: Provision resource
    assert wf.steps[0].method == "POST"
    assert "extracted_id" in wf.steps[0].extract

    # Step 2: Baseline verification
    assert wf.steps[1].method in ("GET", "DELETE")
    assert "{{extracted_id}}" in wf.steps[1].endpoint
    assert wf.steps[1].auth_user == "user1"

    # Step 3: BOLA assertion with User 2
    assert wf.steps[2].auth_user == "user2"
    assert wf.steps[2].assert_denied is True
