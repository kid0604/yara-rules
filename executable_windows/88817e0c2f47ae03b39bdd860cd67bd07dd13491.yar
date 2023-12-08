import "pe"

rule HKTL_Lazagne_Gen_18
{
	meta:
		description = "Detects Lazagne password extractor hacktool"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/AlessandroZ/LaZagne"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		date = "2018-12-11"
		score = 80
		hash1 = "51121dd5fbdfe8db7d3a5311e3e9c904d644ff7221b60284c03347938577eecf"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "lazagne.config.powershell_execute(" ascii
		$x2 = "creddump7.win32." ascii
		$x3 = "lazagne.softwares.windows.hashdump" ascii
		$x4 = ".softwares.memory.libkeepass.common(" ascii

	condition:
		2 of them
}
