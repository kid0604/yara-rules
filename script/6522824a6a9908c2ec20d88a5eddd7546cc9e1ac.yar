rule malware_flubot_webshell
{
	meta:
		description = "Webshell used in FluBot download page"
		author = "JPCERT/CC Incident Response Group"
		hash = "18f154adc2a1267b67d05ea125a3b1991c28651c638f0a00913d601c6237c2bc"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$token = "aG1mN2ZkcXM5dmZ4cDhzNHJ3cXp4YmZ6NmM0M2J3Z2I="
		$param01 = "Zm9yY2VfcmVkaXJlY3Rfb2ZmZXI="
		$param02 = "c3ViX2lkXz"
		$message01 = "RFctVkFMSUQtT0s="
		$message02 = "RFctSU5WQUxJRC1F"
		$message03 = "S1QtVkFMSUQtT0s="
		$message04 = "S1QtSU5WQUxJRC1F"

	condition:
		all of ($message*) or all of ($param*) or $token
}
