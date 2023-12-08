import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_attrib
{
	meta:
		author = "ditekSHen"
		description = "Detects executables using attrib with suspicious attributes attributes"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "attrib +h +r +s" ascii wide

	condition:
		uint16(0)==0x5a4d and any of them
}
