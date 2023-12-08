import "pe"

rule PROPACKv208emphasisonpackedsizelocked
{
	meta:
		author = "malware-lu"
		description = "Detects PROPACKv208 malware based on emphasis on packed size locked"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC ?? 8B EC BE [2] FC E8 [2] 05 [2] 8B C8 E8 [2] 8B }

	condition:
		$a0 at pe.entry_point
}
