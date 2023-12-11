import "pe"

rule TopSpeedv3011989
{
	meta:
		author = "malware-lu"
		description = "Detects TopSpeedv3011989 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E BA [2] 8E DA 8B [3] 8B [3] FF [3] 50 53 }

	condition:
		$a0 at pe.entry_point
}
