import "pe"

rule MALWARE_Win_Fabookie_02
{
	meta:
		author = "ditekSHen"
		description = "Detects Fabookie / NAPAgent"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\"%1\\control.exe\" ncpa.cpl%2" wide
		$s2 = "Elevation:Administrator!new:%s" wide
		$s3 = "quar_qclintfy_mtx" wide
		$s4 = "Software\\Microsoft\\NetworkAccessProtection\\UI\\Branding\\%" wide
		$s5 = "napagent" fullword wide
		$s6 = "napstat.pdb" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of ($s*)
}
