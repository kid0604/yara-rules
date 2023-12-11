rule Malware_MsUpdater_String_in_EXE
{
	meta:
		description = "MSUpdater String in Executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b1a2043b7658af4d4c9395fa77fde18ccaf549bb"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "msupdate.exe" fullword wide
		$x3 = "msupdater.exe" fullword ascii
		$x4 = "msupdater32.exe" fullword ascii
		$x5 = "msupdater32.exe" fullword wide
		$x6 = "msupdate.pif" fullword ascii
		$fp1 = "_msupdate_" wide
		$fp2 = "_msupdate_" ascii
		$fp3 = "/kies" wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (1 of ($x*)) and not (1 of ($fp*))
}
