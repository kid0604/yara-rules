import "pe"

rule SUSP_VULN_DRV_PROCEXP152_May23
{
	meta:
		description = "Detects vulnerable process explorer driver (original file name: PROCEXP152.SYS), often used by attackers to elevate privileges (false positives are possible in cases in which old versions of process explorer are still present on the system)"
		author = "Florian Roth"
		reference = "https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/"
		date = "2023-05-05"
		modified = "2023-07-28"
		score = 50
		hash1 = "cdfbe62ef515546f1728189260d0bdf77167063b6dbb77f1db6ed8b61145a2bc"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "\\ProcExpDriver.pdb" ascii
		$a2 = "\\Device\\PROCEXP152" wide fullword
		$a3 = "procexp.Sys" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
