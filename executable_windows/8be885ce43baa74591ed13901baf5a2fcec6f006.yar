import "pe"

rule PellesC28x45xPelleOrinius
{
	meta:
		author = "malware-lu"
		description = "Detects PellesC28x45xPelleOrinius malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 6A FF 68 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 83 EC }

	condition:
		$a0 at pe.entry_point
}
