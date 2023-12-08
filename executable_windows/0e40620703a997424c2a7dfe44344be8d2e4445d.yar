rule APT_Malware_PutterPanda_Rel
{
	meta:
		description = "Detects an APT malware related to PutterPanda"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "5367e183df155e3133d916f7080ef973f7741d34"
		os = "windows"
		filetype = "executable"

	strings:
		$x0 = "app.stream-media.net" fullword ascii
		$x1 = "File %s does'nt exist or is forbidden to acess!" fullword ascii
		$s6 = "GetProcessAddresss of pHttpQueryInfoA Failed!" fullword ascii
		$s7 = "Connect %s error!" fullword ascii
		$s9 = "Download file %s successfully!" fullword ascii
		$s10 = "index.tmp" fullword ascii
		$s11 = "Execute PE Successfully" fullword ascii
		$s13 = "aa/22/success.xml" fullword ascii
		$s16 = "aa/22/index.asp" fullword ascii
		$s18 = "File %s a Non-Pe File" fullword ascii
		$s19 = "SendRequset error!" fullword ascii
		$s20 = "filelist[%d]=%s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 1 of ($x*)) or (4 of ($s*))
}
