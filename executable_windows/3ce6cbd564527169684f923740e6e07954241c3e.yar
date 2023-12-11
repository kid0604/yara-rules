import "pe"

rule MALWARE_Win_PWSHLoader_RunPE02
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell PE loader / executer. Observed Gorgon TTPs"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "'.Replace('" ascii nocase
		$s2 = "'aspnet_compiler.exe'" ascii
		$s3 = "[Byte[]]$" ascii
		$pe1 = "(77,90," ascii
		$pe2 = "='4D5A" ascii

	condition:
		all of ($s*) and (#pe1>1 or #pe2>1) and #s1>4
}
