import "pe"
import "math"

rule beacon32
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 5"
		os = "windows"
		filetype = "executable"

	strings:
		$name = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"

	condition:
		uint16(0)==0x5A4D and pe.entry_point==0x8b0 and filesize >277KB and filesize <304KB and $name
}
