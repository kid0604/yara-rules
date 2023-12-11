import "pe"

rule ZXProxy
{
	meta:
		author = "ThreatConnect Intelligence Research Team"
		description = "Detects ZXProxy malware communication and file paths"
		os = "windows"
		filetype = "executable"

	strings:
		$C = "\\Control\\zxplug" nocase wide ascii
		$h = "http://www.facebook.com/comment/update.exe" wide ascii
		$S = "Shared a shell to %s:%s Successfully" nocase wide ascii

	condition:
		any of them
}
