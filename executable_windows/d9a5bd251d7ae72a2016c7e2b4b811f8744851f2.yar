import "pe"

rule IndiaBravo_generic
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects the presence of IndiaBravo malware"
		os = "windows"
		filetype = "executable"

	strings:
		$extractDll = "[2] - Extract Dll..." wide
		$createSvc = "[3] - CreateSVC..." wide

	condition:
		all of them
}
