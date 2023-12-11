import "pe"

rule MALWARE_Win_Tardigrade
{
	meta:
		author = "ditekSHen"
		description = "Detects Tardigrade"
		hash1 = "c0976a1fbc3dd938f1d2996a888d0b3a516b432a2c38d788831553d81e2f5858"
		hash2 = "966b2c7c72a28310acd58bb23af4d3c893b2afca264b2d9c0ec42db815c77487"
		hash3 = "88be5da274df704dc7fd9882c661a0afdd35f1ce0a7145e30f51c292abd2a86b"
		hash4 = "cf88926b7d5a5ebbd563d0241aaf83718b77cec56da66bdf234295cc5a91c5fe"
		hash5 = "4afd9f0dde092daeac3f3e6ffb0aee06682b3dba6005d2bd1a914eefd5cc6a30"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd.exe /c echo kOJAdtQoDcMuogIZIl>\"%s\"&exit" fullword ascii
		$x2 = "cmd.exe /c echo HBnBcZPeUevCDQmKGzXxYJHqpzRAbRCQCihOxiLi>\"%s\"&exit" fullword ascii
		$x3 = "cmd.exe /c set kpUUCjoLWLZvJFc=3167 & reg add HKCU\\SOFTWARE\\EQwIobTRgsJ /v PDMXPmqSYnUx /t REG_DWORD /d 10080 & exit" fullword ascii
		$s1 = "ReplaceFileA" ascii
		$s2 = "FlushFileBuffers" ascii
		$s3 = "WaitNamedPipeA" ascii
		$s4 = "ImpersonateNamedPipeClient" ascii
		$s5 = "RegFlushKey" ascii
		$s6 = /cmd\.exe \/c (echo|set)/ ascii
		$s7 = ">\"%s\"&exit" ascii

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and (1 of ($x*) or 6 of ($s*)) and (pe.exports("DllGetClassObject") and pe.exports("DllMain") and pe.exports("DllRegisterServer") and pe.exports("DllUnregisterServer") and pe.exports("InitHelperDll") and pe.exports("StartW"))
}
