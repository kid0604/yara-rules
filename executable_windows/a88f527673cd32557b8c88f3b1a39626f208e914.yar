rule HKTL_PowerKatz_Feb19_1
{
	meta:
		description = "Detetcs a tool used in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Powerkatz32" ascii wide fullword
		$x2 = "Powerkatz64" ascii wide
		$s1 = "GetData: not found taskName" fullword ascii wide
		$s2 = "GetRes Ex:" fullword ascii wide

	condition:
		1 of ($x*) and 1 of ($s*)
}
