import "pe"
import "math"

rule GIFCloaked_Webshell_A
{
	meta:
		description = "Looks like a webshell cloaked as GIF"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "input type"
		$s1 = "<%eval request"
		$s2 = "<%eval(Request.Item["
		$s3 = "LANGUAGE='VBScript'"
		$s4 = "$_REQUEST" fullword
		$s5 = ";eval("
		$s6 = "base64_decode"
		$fp1 = "<form name=\"social_form\""

	condition:
		uint32(0)==0x38464947 and (1 of ($s*)) and not 1 of ($fp*)
}
