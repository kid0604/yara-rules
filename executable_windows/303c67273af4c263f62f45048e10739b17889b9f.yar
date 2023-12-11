import "pe"

rule INDICATOR_EXE_Packed_LibZ
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with LibZ"
		snort2_sid = "930055-930057"
		snort3_sid = "930019-930020"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "LibZ.Injected" fullword ascii
		$s2 = "{0:N}.dll" fullword wide
		$s3 = "asmz://(?<guid>[0-9a-fA-F]{32})/(?<size>[0-9]+)(/(?<flags>[a-zA-Z0-9]*))?" fullword wide
		$s4 = "Software\\Softpark\\LibZ" fullword wide
		$s5 = "(AsmZ/{" wide
		$s6 = "asmz://" ascii
		$s7 = "GetRegistryDWORD" ascii
		$s8 = "REGISTRY_KEY_NAME" fullword ascii
		$s9 = "REGISTRY_KEY_PATH" fullword ascii
		$s10 = "InitializeDecoders" fullword ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
