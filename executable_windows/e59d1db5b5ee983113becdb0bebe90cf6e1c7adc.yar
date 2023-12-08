rule INDICATOR_KB_ID_UNK01
{
	meta:
		author = "ditekShen"
		description = "Detects Amadey executables with specific email addresses found in the code signing certificate"
		hash1 = "37d08a64868c35c5bae8f5155cc669486590951ea80dd9da61ec38defb89a146"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "etienne@tetracerous.br" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and any of them
}
