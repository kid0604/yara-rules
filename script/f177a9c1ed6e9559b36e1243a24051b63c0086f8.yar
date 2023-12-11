rule SUSP_PowerShell_Caret_Obfuscation_2
{
	meta:
		description = "Detects powershell keyword obfuscated with carets"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-07-20"
		os = "windows"
		filetype = "script"

	strings:
		$r1 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l\^l/ ascii wide nocase fullword
		$r2 = /p\^o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword

	condition:
		1 of them
}
