import "pe"
import "math"

rule CobaltStrike_Malicious_HTA
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 16"
		os = "windows"
		filetype = "script"

	strings:
		$var_shell = "CreateObject(\"Wscript.Shell\")" nocase
		$RunPowerShell = "powershell -nop -w hidden -encodedcommand " nocase
		$DropFile = ".Write Chr(CLng(\"&H\" & Mid(" nocase
		$Obfuscator = "&\"Long\"&Chr(44)&" nocase
		$Script = "<script language=\"vbscript\">" nocase

	condition:
		$var_shell and $Script and 3 of them
}
