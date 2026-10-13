@echo off
rem Start Claude Code in the project root with the orchestrator agent.
cd /d "%~dp0.."
claude --agent orchestrator %*
