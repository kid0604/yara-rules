rule APT_RANSOM_Lockbit_ForensicArtifacts_Nov23
{
	meta:
		description = "Detects patterns found in Lockbit TA attacks exploiting Citrixbleed vulnerability CVE 2023-4966"
		author = "Florian Roth"
		date = "2023-11-22"
		score = 75
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
		id = "04bde599-2a5b-5a33-a6f1-67d57a564946"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "taskkill /f /im sqlwriter.exe /im winmysqladmin.exe /im w3sqlmgr.exe"
		$x2 = " 1> \\\\127.0.0.1\\admin$\\__"

	condition:
		1 of ($x*)
}
