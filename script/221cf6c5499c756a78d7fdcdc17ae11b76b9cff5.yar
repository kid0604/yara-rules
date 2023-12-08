import "pe"

rule MALWARE_Win_PWSHLoader_RunPE01
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell PE loader / executer. Observed Gorgon TTPs"
		os = "windows"
		filetype = "script"

	strings:
		$rp1 = "GetType('RunPe.RunPe'" ascii
		$rp2 = "GetType(\"RunPe.RunPe\"" ascii
		$rm1 = "GetMethod('Run'" ascii
		$rm2 = "GetMethod(\"Run\"" ascii
		$s1 = ".Invoke(" ascii
		$s2 = "[Reflection.Assembly]::Load(" ascii

	condition:
		all of ($s*) and 1 of ($rp*) and 1 of ($rm*)
}
