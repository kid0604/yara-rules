import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_ShredFileSteps
{
	meta:
		author = "ditekSHen"
		description = "Detects executables embedding/copying file shredding steps"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 55 00 00 00 aa 00 00 00 92 49 24 00 49 24 92 00
                24 92 49 00 00 00 00 00 11 00 00 00 22 00 00 00
                33 00 00 00 44 00 00 00 66 00 00 00 88 00 00 00
                99 00 00 00 bb 00 00 00 cc 00 00 00 dd 00 00 00
                ee 00 00 00 ff 00 00 00 6d b6 db 00 b6 db 6d 00
                db 6d b6 }

	condition:
		uint16(0)==0x5a4d and all of them
}
