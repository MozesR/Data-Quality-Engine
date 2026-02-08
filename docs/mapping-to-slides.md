# Mapping to presentation requirements

## Implemented in demo

- Learn/Detect/Correct/Prevent/Use workflow structure (simplified)
- DQ reference rule concepts represented in `mcp-server` rule catalogs
- DQ assessment rule types: not-null, ranges, allowed values, regex
- Correction rules: default/proxy style correction (`fill_default_if_null`)
- Workflow management with execution tracking (`workflow_runs`)
- Data source connection hosted in MCP server
- Web-based client operating workflows via MCP tools
- Data quality index output (`quality_index`)
- LLM process configurable via external config file

## Production baseline delivered

- Multi-replica service topology
- Swarm/K8s-ready manifests
- Config/secrets separation
- Externalized images and environment variables

## Not yet implemented (next iterations)

- Full ML lifecycle for prediction/correction training and validation
- Rule lifecycle governance UI (draft/production/obsolete)
- Dataset profile over time and trend thresholds
- Approval workflow with role-based decisioning
- Full lineage and impact simulation
