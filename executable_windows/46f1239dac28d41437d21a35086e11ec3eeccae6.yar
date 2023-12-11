import "pe"

rule misc_iocs
{
	meta:
		author = "@patrickrolsen"
		maltype = "Misc."
		version = "0.1"
		reference = "N/A"
		description = "Detects miscellaneous indicators of compromise"
		os = "windows"
		filetype = "executable"

	strings:
		$doc = {D0 CF 11 E0}
		$s1 = "dw20.exe"
		$s2 = "cmd /"

	condition:
		($doc at 0) and (1 of ($s*))
}
