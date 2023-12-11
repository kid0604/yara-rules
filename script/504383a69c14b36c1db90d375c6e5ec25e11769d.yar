rule EquationGroup_promptkill
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file promptkill"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "b448204503849926be249a9bafbfc1e36ef16421c5d3cfac5dac91f35eeaa52d"
		os = "linux"
		filetype = "script"

	strings:
		$x1 = "exec(\"xterm $xargs -e /current/tmp/promptkill.kid.$tag $pid\");" fullword ascii
		$x2 = "$xargs=\"-title \\\"Kill process $pid?\\\" -name \\\"Kill process $pid?\\\" -bg white -fg red -geometry 202x19+0+0\" ;" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
