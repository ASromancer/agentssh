// Package plugin is the Claude Code plugin (skill + hook). The skill is
// embedded so 'agentssh install-hooks claude' installs the same text.
package plugin

import _ "embed"

//go:embed skills/agentssh/SKILL.md
var Skill string
