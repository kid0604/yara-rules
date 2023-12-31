rule malware_multi_vesche_basicrat
{
	meta:
		description = "cross-platform Python 2.x Remote Access Trojan (RAT)"
		reference = "https://github.com/vesche/basicRAT"
		author = "@mimeframe"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$a1 = "HKCU Run registry key applied" wide ascii
		$a2 = "HKCU Run registry key failed" wide ascii
		$a3 = "Error, platform unsupported." wide ascii
		$a4 = "Persistence successful," wide ascii
		$a5 = "Persistence unsuccessful," wide ascii

	condition:
		all of ($a*)
}
