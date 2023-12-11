import "math"
import "pe"

rule cobaltstrike_beacon_in_memory
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 12"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "beacon.x64.dll" fullword
		$s2 = "F    %I64d   %02d/%02d/%02d %02d:%02d:%02d   %s" fullword

	condition:
		all of them
}
