rule SUSP_Msdt_Artefact_Jun22_2
{
	meta:
		description = "Detects suspicious pattern in msdt diagnostics log (e.g. CVE-2022-30190 / Follina exploitation)"
		author = "Christian Burkard"
		date = "2022-06-01"
		modified = "2022-07-29"
		reference = "https://twitter.com/nas_bench/status/1531718490494844928"
		score = 75
		os = "windows"
		filetype = "script"

	strings:
		$a1 = "<ScriptError><Data id=\"ScriptName\" name=\"Script\">TS_ProgramCompatibilityWizard.ps1" ascii
		$x1 = "/../../" ascii
		$x2 = "$(Invoke-Expression" ascii
		$x3 = "$(IEX(" ascii nocase

	condition:
		uint32(0)==0x6D783F3C and $a1 and 1 of ($x*)
}
