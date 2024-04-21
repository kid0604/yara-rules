import "pe"

rule win_iceid_core_ldr_202104
{
	meta:
		author = "Thomas Barabosch, Telekom Security"
		date = "2021-04-13"
		description = "2021 loader for Bokbot / Icedid core (license.dat)"
		os = "windows"
		filetype = "executable"

	strings:
		$internal_name = "sadl_64.dll" fullword
		$string0 = "GetCommandLineA" fullword
		$string1 = "LoadLibraryA" fullword
		$string2 = "ProgramData" fullword
		$string3 = "SHLWAPI.dll" fullword
		$string4 = "SHGetFolderPathA" fullword
		$string5 = "DllRegisterServer" fullword
		$string6 = "update" fullword
		$string7 = "SHELL32.dll" fullword
		$string8 = "CreateThread" fullword

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ($internal_name or all of ($s*)) or all of them
}
