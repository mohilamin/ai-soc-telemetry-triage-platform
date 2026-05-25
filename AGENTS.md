# AGENTS.md

You are building a production-style Cybersecurity Data Engineering + AI SOC Triage project.

Project name:
AI SOC Telemetry Triage Platform

Primary goal:
Build a local SOC telemetry triage platform that simulates multi-source security logs, injects attack scenarios, applies detection rules, correlates alerts into incidents, scores risk, estimates blast radius, and generates analyst-ready investigation outputs.

## Business Context

Modern SOC teams receive noisy alerts across identity, endpoint, cloud, network, SaaS, email, DNS, firewall, and AI application systems. The hard problem is not alert generation. The hard problem is correlation, triage, prioritization, false-positive reduction, and response evidence.

## Build Principles

- Use Python 3.12.
- Use synthetic data only.
- Do not use real sensitive data.
- Keep V0.1 deterministic and locally runnable.
- Every alert must have evidence.
- Every incident must have severity, confidence, affected assets, and recommended action.
- Every detection rule must be documented.
- Every attack scenario must have expected detections.
- Every major pipeline stage must have tests.
- README must be public-facing and recruiter-friendly.

## Commit Message Requirements

- Do not use generic AI-like commit messages such as "Build project," "Create files," "Build SOC platform," or "Build dashboard."
- Prefer Conventional Commit style such as `feat(detection): add Sigma-style rule engine`.

## Definition of Done

A task is complete only when code runs locally, tests pass, ruff passes, README is detailed and diagram-rich, synthetic telemetry exists, attack scenarios exist, detection rules exist, MITRE-style mapping exists, alerts exist, incidents exist, analyst queue exists, timelines exist, runbooks exist, scorecards exist, dashboard and API can launch, GitHub Actions and Docker exist, and no real sensitive data is used.

