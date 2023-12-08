import "math"
import "pe"

rule hacktool_windows_cobaltstrike_powershell_alt_1
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 4"
		os = "windows"
		filetype = "script"

	strings:
		$ps1 = "Set-StrictMode -Version 2"
		$ps2 = "func_get_proc_address"
		$ps3 = "func_get_delegate_type"
		$ps4 = "FromBase64String"
		$ps5 = "VirtualAlloc"
		$ps6 = "var_code"
		$ps7 = "var_buffer"
		$ps8 = "var_hthread"

	condition:
		$ps1 at 0 and filesize <1000KB and 7 of ($ps*)
}
