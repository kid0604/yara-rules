import "pe"

rule MACROMAIL_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting MACROMAIL APT1 threat"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "svcMsn.dll" wide ascii
		$s2 = "RundllInstall" wide ascii
		$s3 = "Config service %s ok." wide ascii
		$s4 = "svchost.exe" wide ascii

	condition:
		all of them
}
