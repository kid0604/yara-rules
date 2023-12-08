import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_ClearMyTracksByProcess
{
	meta:
		author = "ditekSHen"
		description = "Detects executables calling ClearMyTracksByProcess"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "InetCpl.cpl,ClearMyTracksByProcess" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and any of them
}
