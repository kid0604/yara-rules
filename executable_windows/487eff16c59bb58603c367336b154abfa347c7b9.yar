import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_Reversed
{
	meta:
		author = "ditekSHen"
		description = "Detects reversed executables. Observed N-stage drop"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "edom SOD ni nur eb tonnac margorp sihT" ascii

	condition:
		uint16( filesize -0x2)==0x4d5a and $s1
}
