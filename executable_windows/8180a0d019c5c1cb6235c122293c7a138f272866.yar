rule HKTL_Unknown_Feb19_1
{
	meta:
		description = "Detetcs a tool used in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "not a valid timeout format!" ascii wide fullword
		$x2 = "host can not be empty!" ascii wide fullword
		$x3 = "not a valid port format!" ascii wide fullword
		$x4 = "{0} - {1} TTL={2} time={3}" ascii wide fullword
		$x5 = "ping count is not a correct format!" ascii wide fullword
		$s1 = "The result is too large,program store to '{0}'.Please download it manully." fullword ascii wide
		$s2 = "C:\\Windows\\temp\\" ascii wide

	condition:
		1 of ($x*) or 2 of them
}
