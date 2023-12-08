import "pe"

rule Mimikatz_Memory_Rule_1_alt_1 : APT
{
	meta:
		author = "Florian Roth"
		date = "2014-12-22"
		modified = "2023-07-04"
		score = 70
		nodeepdive = 1
		description = "Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "sekurlsa::wdigest" fullword ascii
		$s2 = "sekurlsa::logonPasswords" fullword ascii
		$s3 = "sekurlsa::minidump" fullword ascii
		$s4 = "sekurlsa::credman" fullword ascii
		$fp1 = "\"x_mitre_version\": " ascii
		$fp2 = "{\"type\":\"bundle\","
		$fp3 = "use strict" ascii fullword
		$fp4 = "\"url\":\"https://attack.mitre.org/" ascii

	condition:
		1 of ($s*) and not 1 of ($fp*)
}
