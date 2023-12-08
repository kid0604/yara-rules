import "pe"

rule Turla_Mal_Script_Jan18_1
{
	meta:
		description = "Detects Turla malicious script"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://ghostbin.com/paste/jsph7"
		date = "2018-01-19"
		hash1 = "180b920e9cea712d124ff41cd1060683a14a79285d960e17f0f49b969f15bfcc"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = ".charCodeAt(i % " ascii
		$s2 = "{WScript.Quit();}" fullword ascii
		$s3 = ".charAt(i)) << 10) |" ascii
		$s4 = " = WScript.Arguments;var " ascii
		$s5 = "= \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";var i;" ascii

	condition:
		filesize <200KB and 2 of them
}
