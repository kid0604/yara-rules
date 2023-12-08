import "pe"
import "math"

rule StoneDrill_main_sub
{
	meta:
		author = "Kaspersky Lab"
		description = "Rule to detect StoneDrill (decrypted) samples"
		hash1 = "d01781f1246fd1b64e09170bd6600fe1"
		hash2 = "ac3c25534c076623192b9381f926ba0d"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		version = "1.0"
		os = "windows"
		filetype = "executable"

	strings:
		$code = {B8 08 00 FE 7F FF 30 8F 44 24 ?? 68 B4 0F 00 00 FF 15 ?? ?? ?? 00 B8 08 00 FE 7F FF 30 8F 44 24 ?? 8B ?? 24 [1 - 4] 2B ?? 24 [6] F7 ?1 [5 - 12] 00}

	condition:
		uint16(0)==0x5A4D and $code and filesize <5000000
}
