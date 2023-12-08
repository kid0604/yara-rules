rule INDICATOR_TOOL_ChromeCookiesView
{
	meta:
		author = "ditekSHen"
		description = "Detects ChromeCookiesView"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "AddRemarkCookiesTXT" fullword wide
		$s2 = "Decrypt cookies" wide
		$s3 = "/scookiestxt" fullword wide
		$s4 = "/deleteregkey" fullword wide
		$s5 = "Cookies.txt Format" wide
		$s6 = "# Netscape HTTP Cookie File" wide
		$pdb = "\\ChromeCookiesView\\Release\\ChromeCookiesView.pdb" ascii

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) or (($pdb) and 2 of ($s*)))
}
