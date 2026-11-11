// Package plugin is the Claude Code plugin (skill + hook). The skill is
// embedded so 'ostiary install-hooks claude' installs the same text.
package plugin

import _ "embed"

//go:embed skills/ostiary/SKILL.md
var Skill string
