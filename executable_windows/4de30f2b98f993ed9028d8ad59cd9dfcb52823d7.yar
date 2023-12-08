rule Windows_Ransomware_Ryuk_878bae7e : beta
{
	meta:
		author = "Elastic Security"
		id = "878bae7e-1e53-4648-93aa-b4075eef256d"
		fingerprint = "93a501463bb2320a9ab824d70333da2b6f635eb5958d6f8de43fde3a21de2298"
		creation_date = "2020-04-30"
		last_modified = "2021-08-23"
		description = "Identifies RYUK ransomware"
		threat_name = "Windows.Ransomware.Ryuk"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$b2 = "RyukReadMe.html" wide fullword
		$b3 = "RyukReadMe.txt" wide fullword

	condition:
		1 of ($b*)
}
