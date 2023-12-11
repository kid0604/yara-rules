rule APT_Malware_PutterPanda_MsUpdater_3
{
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "464149ff23f9c7f4ab2f5cadb76a4f41f969bed0"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "msupdater.exe" fullword ascii
		$s1 = "Explorer.exe \"" fullword ascii
		$s2 = "FAVORITES.DAT" fullword ascii
		$s4 = "COMSPEC" fullword ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}
