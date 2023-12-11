import "math"
import "pe"

rule StoneDrill_main_sub_alt_1
{
	meta:
		author = "Kaspersky Lab"
		description = "Rule to detect StoneDrill (decrypted) samples"
		hash = "d01781f1246fd1b64e09170bd6600fe1"
		hash = "ac3c25534c076623192b9381f926ba0d"
		version = "1.0"
		os = "windows"
		filetype = "executable"

	strings:
		$code = {B8 08 00 FE 7F FF 30 8F 44 24 ?? 68 B4 0F 00 00 FF 15 ?? ?? ?? 00 B8 08 00 FE 7F FF
30 8F 44 24 ?? 8B ?? 24 [1 - 4] 2B ?? 24 [6] F7 ?1 [5 - 12] 00}

	condition:
		uint16(0)==0x5A4D and $code and filesize <5000000
}
