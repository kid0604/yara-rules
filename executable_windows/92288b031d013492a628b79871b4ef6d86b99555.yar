import "pe"
import "math"

rule CobaltStrike_imphashes
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 17"
		os = "windows"
		filetype = "executable"

	condition:
		pe.imphash()=="829da329ce140d873b4a8bde2cbfaa7e" or pe.imphash()=="dc25ee78e2ef4d36faa0badf1e7461c9"
}
