import "pe"

rule SUSP_NK_MAL_M_Hunting_POOLRAT
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		old_rule_name = "APT_NK_MAL_M_Hunting_POOLRAT"
		score = 70
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		description = "Detects strings found in POOLRAT malware"
		hash1 = "451c23709ecd5a8461ad060f6346930c"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "name=\"uid\"%s%s%u%s" ascii wide
		$s2 = "name=\"session\"%s%s%u%s" ascii wide
		$s3 = "name=\"action\"%s%s%s%s" ascii wide
		$s4 = "name=\"token\"%s%s%u%s" ascii wide
		$str1 = "--N9dLfqxHNUUw8qaUPqggVTpX-" wide ascii nocase

	condition:
		any of ($s*) or $str1
}
