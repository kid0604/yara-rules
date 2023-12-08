import "pe"
import "math"

rule hta_ps1
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 9"
		os = "windows"
		filetype = "script"

	strings:
		$str = "var_shell.run \"powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8A"

	condition:
		uint16(0)!=0x5A4D and $str
}
