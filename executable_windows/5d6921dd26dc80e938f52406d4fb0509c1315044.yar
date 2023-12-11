rule INDICATOR_TOOL_EdgeCookiesView
{
	meta:
		author = "ditekSHen"
		description = "Detects EdgeCookiesView"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "AddRemarkCookiesTXT" fullword wide
		$s2 = "# Netscape HTTP Cookie File" fullword wide
		$s3 = "/scookiestxt" fullword wide
		$s4 = "/deleteregkey" fullword wide
		$s5 = "Load cookies from:" wide
		$s6 = "Old cookies folder of Edge/IE" wide
		$pdb = "\\EdgeCookiesView\\Release\\EdgeCookiesView.pdb" ascii

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) or (($pdb) and 2 of ($s*)))
}
