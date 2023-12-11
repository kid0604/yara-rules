rule CN_Honker_getlsasrvaddr
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file getlsasrvaddr.exe - WCE Amplia Security"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2022-12-21"
		score = 70
		hash = "a897d5da98dae8d80f3c0a0ef6a07c4b42fb89ce"
		os = "windows"
		filetype = "executable"

	strings:
		$s8 = "pingme.txt" fullword ascii
		$s16 = ".\\lsasrv.pdb" ascii
		$s20 = "Addresses Found: " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
