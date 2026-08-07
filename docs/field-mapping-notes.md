Field Mapping: Sigma Standard Fields vs. Lab Raw Schema
The gap

Sigma rules in this repo are written using standard Sigma field names (Image, CommandLine, TargetObject, etc.) — this is intentional, and keeps the rules portable across any properly-mapped environment.

However, this lab's Winlogbeat setup ships raw Sysmon fields with no ECS translation layer applied. That translation is normally handled automatically by Elastic Agent's Windows integration (which the TCM course lab environment uses) — but this lab runs standalone Winlogbeat pointed at just the Sysmon channel, so no such mapping happens.

Practical effect

sigma-cli's ecs_windows pipeline assumes ECS field names that don't exist in this lab's raw data. Converting a rule with -p ecs_windows produces a query that will return zero results here, even though the rule logic itself is correct.

Manual translation table

When hunting a rule against this lab's data in Discover, translate field names manually:

Sigma field	ECS (ecs_windows pipeline)	This lab's raw schema
TargetObject	registry.path	winlog.event_data.TargetObject
Image	process.executable	winlog.event_data.Image
CommandLine	process.command_line	winlog.event_data.CommandLine
Validating rules locally

Use --without-pipeline instead of -p ecs_windows to validate syntax without assuming a field mapping that doesn't apply here:

powershell
sigma convert -t lucene --without-pipeline <rule>.yml

This confirms the rule logic is sound, using standard Sigma field names. Manually substitute field names per the table above when constructing the actual hunt query in Discover.

Longer-term fix (not yet done)

Two options to close this gap properly, so manual translation isn't needed every time:

1. A custom Elasticsearch ingest pipeline that renames raw winlog.event_data.* fields to their ECS equivalents on ingest.
2. A custom pySigma processing pipeline that maps standard Sigma fields directly to this lab's raw schema, so sigma convert can target it directly (-p raw_winlogbeat or similar).

Parked as a future task — worth its own dedicated session rather than solving mid-flow while building a rule.