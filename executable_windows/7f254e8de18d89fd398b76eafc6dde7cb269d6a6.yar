rule CN_Honker_exp_ms11080
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11080.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "[*] command add user 90sec 90sec" fullword ascii
		$s6 = "[*] Add to Administrators success" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <840KB and all of them
}
