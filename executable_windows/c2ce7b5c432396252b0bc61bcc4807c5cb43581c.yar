rule MAL_CRIME_Unknown_ISO_Jun21_1 : ISO POWERSHELL LNK
{
	meta:
		author = "Nils Kuhnert"
		date = "2021-06-04"
		description = "Triggers on ISO files that mimick NOBELIUM TTPs, but uses LNK files that call powershell instead."
		hash1 = "425dbed047dd2ce760d0848ebf7ad04b1ca360f111d557fc7bf657ae89f86d36"
		hash2 = "f6944b6bca627e219d9c5065f214f95eb2226897a3b823b645d0fd78c281b149"
		hash3 = "14d70a8bdd64e9a936c2dc9caa6d4506794505e0e3870e3a25d9d59bcafb046e"
		hash4 = "9b2ca8eb6db34b07647a74171a5ff4c0a2ca8000da9876ed2db6361958c5c080"
		os = "windows"
		filetype = "executable"

	strings:
		$uid = "S-1-5-21-1437133880-1006698037-385855442-1004" wide
		$magic = "CD001" ascii

	condition:
		filesize <5MB and all of them
}
