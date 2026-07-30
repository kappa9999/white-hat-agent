from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastmcp import Client

from white_hat_agent.mcp_server import create_server
from white_hat_agent.workspace import Workspace

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
async def test_namespaced_mcp_surface_and_structured_results(tmp_path) -> None:
    Workspace.initialize(tmp_path)
    server = create_server(tmp_path)

    async with Client(server) as client:
        listed_tools = await client.list_tools()
        tools = {tool.name for tool in listed_tools}
        resources = {str(resource.uri) for resource in await client.list_resources()}
        prompts = {prompt.name for prompt in await client.list_prompts()}
        templates = {str(item.uriTemplate) for item in await client.list_resource_templates()}

        assert {
            "knowledge_search",
            "knowledge_intake",
            "knowledge_learning_candidates",
            "knowledge_intake_learning",
            "knowledge_compose",
            "capability_search",
            "capability_gaps",
            "adapter_search",
            "adapter_status",
            "adapter_resolve",
            "adapter_ensure",
            "adapter_plan_provision",
            "adapter_provision",
            "adapter_conform",
            "adapter_execute",
            "adapter_search_knowledge",
            "adapter_read_knowledge",
            "campaign_plan",
            "campaign_scope_check",
            "campaign_enqueue",
            "intelligence_sync",
            "intelligence_status",
            "intelligence_epss_history",
            "opportunity_add",
            "opportunity_rank",
            "evidence_import_file",
            "evidence_add_finding",
            "fleet_claim",
            "discovery_verify",
        }.issubset(tools)
        assert "whitehat://status" in resources
        assert "whitehat://knowledge/corpus/manifest" in resources
        assert "whitehat://capability/capabilities/catalog" in resources
        assert "whitehat://adapter/adapters/catalog" in resources
        assert "whitehat://knowledge/playbook/{playbook_id}" in templates
        assert "knowledge_compile_submission" in prompts
        sync_tool = next(tool for tool in listed_tools if tool.name == "intelligence_sync")
        source_items = sync_tool.inputSchema["properties"]["sources"]["anyOf"][0]["items"]
        assert source_items["enum"] == ["cisa-kev", "cve-list-v5", "nvd", "osv"]

        adapter_search = await client.call_tool("adapter_search", {"query": "reverse"})
        assert not adapter_search.is_error
        assert adapter_search.structured_content["result"][0]["adapter"]["adapter_id"] == "ghidra"

        intelligence_status = await client.call_tool("intelligence_status", {})
        assert not intelligence_status.is_error
        assert intelligence_status.structured_content["initialized"] is True

        search = await client.call_tool("knowledge_search", {"query": "http"})
        assert not search.is_error
        assert search.structured_content["result"][0]["playbook_id"] == "http-response-surface-map"

        intake = await client.call_tool(
            "knowledge_intake",
            {
                "text": "1. Capturar la línea base.\n2. Verificar la diferencia.",
                "language": "es",
                "title": "Diferencial HTTP",
            },
        )
        assert not intake.is_error
        assert intake.structured_content["draft_playbook"]["metadata"]["original_languages"] == ["es"]

        planning_payload = yaml.safe_load(
            (REPOSITORY_ROOT / "examples/campaigns/planning-request.yaml").read_text(encoding="utf-8")
        )
        planned = await client.call_tool("campaign_plan", {"request": planning_payload})
        assert not planned.is_error
        assert planned.structured_content["complete"] is True
        assert len(planned.structured_content["targets"][0]["stages"]) == 2
