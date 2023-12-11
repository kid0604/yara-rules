import "pe"

rule zbot : banker
{
	meta:
		author = "malware-lu"
		description = "Detects Zbot banker malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "__SYSTEM__" wide
		$b = "*tanentry*"
		$c = "*<option"
		$d = "*<select"
		$e = "*<input"

	condition:
		($a and $b) or ($c and $d and $e)
}
