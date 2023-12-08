import "pe"

rule APT_DeputyDog_alt_1
{
	meta:
		Author = "FireEye Labs"
		Date = "2013/09/21"
		Description = "detects string seen in samples used in 2013-3893 0day attacks"
		Reference = "https://www.fireeye.com/blog/threat-research/2013/09/operation-deputydog-zero-day-cve-2013-3893-attack-against-japanese-targets.html"
		description = "detects string seen in samples used in 2013-3893 0day attacks"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = {4d 5a}
		$a = "DGGYDSYRL"

	condition:
		($mz at 0) and $a
}
