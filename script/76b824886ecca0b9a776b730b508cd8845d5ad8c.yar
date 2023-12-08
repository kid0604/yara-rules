import "pe"

rule MALWARE_Osx_LamePyre
{
	meta:
		description = "Detects LamePyre"
		os = "macos"
		filetype = "script"

	strings:
		$s1 = "/Automator/Run Shell" ascii
		$s2 = "curl " ascii
		$s3 = "base64" ascii
		$s4 = "screencapture" ascii
		$s5 = "handler.php"
		$s6 = "zip" ascii
		$ps1 = "base64.b64decode" ascii
		$ps2 = "dXJsbGliM" ascii
		$ps3 = "c3VicHJvY2Vz" ascii
		$ps4 = "aW5kZXguYXN" ascii
		$sp5 = "YWRkaGVhZGVy" ascii

	condition:
		all of ($ps*) or 5 of ($s*)
}
