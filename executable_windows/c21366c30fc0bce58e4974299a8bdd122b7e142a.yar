import "pe"

rule callTogether_certificate
{
	meta:
		Author = "Fireeye Labs"
		Date = "2014/11/03"
		Description = "detects binaries signed with the CallTogether certificate"
		Reference = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"
		description = "Detects binaries signed with the CallTogether certificate"
		os = "windows"
		filetype = "executable"

	strings:
		$serial = { 45 21 56 C3 B3 FB 01 76 36 5B DB 5B 77 15 BC 4C }
		$o = "CallTogether, Inc."

	condition:
		$serial and $o
}
