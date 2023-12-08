import "pe"

rule CN_disclosed_20180208_Mal1
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		date = "2018-02-08"
		hash1 = "173d69164a6df5bced94ab7016435c128ccf7156145f5d26ca59652ef5dcd24e"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%SystemRoot%\\system32\\termsrvhack.dll" fullword ascii
		$x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
		$a1 = "taskkill /f /im cmd.exe" fullword ascii
		$a2 = "taskkill /f /im mstsc.exe" fullword ascii
		$a3 = "taskkill /f /im taskmgr.exe" fullword ascii
		$a4 = "taskkill /f /im regedit.exe" fullword ascii
		$a5 = "taskkill /f /im mmc.exe" fullword ascii
		$s1 = "K7TSecurity.exe" fullword ascii
		$s2 = "ServUDaemon.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (pe.imphash()=="28e3a58132364197d7cb29ee104004bf" or 1 of ($x*) or 3 of them )
}
