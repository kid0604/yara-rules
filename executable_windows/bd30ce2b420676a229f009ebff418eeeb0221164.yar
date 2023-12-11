import "math"
import "pe"

rule ps_alt_1
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 6"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "$var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)"
		$str2 = "[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)"

	condition:
		uint16(0)!=0x5A4D and $str1 and $str2
}
