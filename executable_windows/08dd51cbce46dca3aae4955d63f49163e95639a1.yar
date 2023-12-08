import "dotnet"

rule Prometei_PDB
{
	meta:
		id = "6RxW5l6ySxPS5K2HD7b6wX"
		fingerprint = "c9342fa61b7e5e711016dab5e6360e836726cf622feed88da92b7aaa4dd79f4a"
		version = "1.0"
		first_imported = "2023-03-24"
		last_modified = "2023-03-24"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies debug paths for Prometei botnet."
		category = "MALWARE"
		malware = "PROMETEI"
		malware_type = "BOT"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
		os = "windows"
		filetype = "executable"

	strings:
		$ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\walker\\/ ascii wide
		$ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\prometei\\/ ascii wide
		$ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\misc\\/ ascii wide

	condition:
		any of them
}
