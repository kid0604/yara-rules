rule Linux_Worm_Generic_98efcd38
{
	meta:
		author = "Elastic Security"
		id = "98efcd38-d579-46f7-a8f8-360f799a5078"
		fingerprint = "d6cec73bb6093dbc6d26566c174d0d0f6448f431429edef0528c9ec1c83177fa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Worm.Generic"
		reference_sample = "87507f5cd73fffdb264d76db9b75f30fe21cc113bcf82c524c5386b5a380d4bb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Worm.Generic"
		filetype = "executable"

	strings:
		$a = { 24 14 75 E1 8B 5A 24 01 EB 66 8B 0C 4B 8B 5A 1C 01 EB 8B 04 8B }

	condition:
		all of them
}
