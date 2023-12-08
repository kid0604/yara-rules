import "math"
import "pe"

rule CobaltStrike_hta_pe
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 7"
		os = "windows"
		filetype = "script"

	strings:
		$reg1 = /var_tempexe = var_basedir & \"\\\" & \"[A-z]{1,20}.exe\"\s*Set var_stream = var_obj.CreateTextFile\(var_tempexe, true , false\)/

	condition:
		uint16(0)!=0x5A4D and $reg1
}
