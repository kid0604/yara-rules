import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_Go_GoLazagne
{
	meta:
		author = "ditekSHen"
		description = "Detects Go executables using GoLazagne"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/goLazagne/" ascii nocase
		$s2 = "Go build ID:" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
