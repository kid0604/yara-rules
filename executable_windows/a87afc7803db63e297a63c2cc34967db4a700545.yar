import "dotnet"

rule Prometei_Dotnet
{
	meta:
		id = "2tFf2nXDFh5zWf8bp0syJ8"
		fingerprint = "efcf00534325da6e45ee56e96fdc7e8063cb20706eef6765cc220a4335220a61"
		version = "1.0"
		first_imported = "2023-03-24"
		last_modified = "2023-03-24"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies dotnet modules used by Prometei botnet, specifically BlueKeep and NetHelper."
		category = "MALWARE"
		malware = "PROMETEI"
		malware_type = "BOT"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
		os = "windows"
		filetype = "executable"

	strings:
		$crypt = {13 30 05 00 DB 00 00 00 0? 00 00 11 20 00 01 00 00 8D ?? 00 00 01 13 05 20 00 01 00 00 8D ?? 00 00 01 13 06 03 8E 69 8D ?? 00 00 01 13 07 16 0B 2B 14 11 05 07 02 07 02 8E 69 5D 91 9E 11 06 07 07 9E 07 17 58 0B 07 20 00 01 00 00 32 E4 16 16 0B 0C 2B 2A 08 11 06 07 94 58 11 05 07 94 58 20 00 01 00 00 5D 0C 11 06 07 94 13 04 11 06 07 11 06 08 94 9E 11 06 08 11 04 9E 07 17 58 0B 07 20 00 01 00 00 32 CE 16 16 0B 16 0C 0A 2B 50 06 17 58 0A 06 20 00 01 00 00 5D 0A 08 11 06 06 94 58 0C 08 20 00 01 00 00 5D 0C 11 06 06 94 13 04 11 06 06 11 06 08 94 9E 11 06 08 11 04 9E 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5D 94 0D 11 07 07 03 07 91 09 61 D2 9C 07 17 58 0B 07 03 8E 69 32 AA 11 07 2A}

	condition:
		$crypt or dotnet.typelib=="daee89b2-0055-46ce-bbab-abb621d6bef1" or dotnet.typelib=="6e74992f-648e-471f-9879-70f57b73ec8d"
}
