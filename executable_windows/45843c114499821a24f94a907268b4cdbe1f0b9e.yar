import "pe"

rule tElock098SpecialBuildforgotheXer
{
	meta:
		author = "malware-lu"
		description = "Detects tElock098 special build for gotheXer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 99 D7 FF FF 00 00 00 [4] AA [2] 00 00 00 00 00 00 00 00 00 CA }

	condition:
		$a0 at pe.entry_point
}
