rule obfuscation_powershell_special_chars
{
	meta:
		author = "RussianPanda"
		description = "Detects PowerShell special character obfuscation"
		reference = "https://perl-users.jp/articles/advent-calendar/2010/sym/11"
		date = "1/12/2024"
		hash = "d77efad78ef3afc5426432597ba129141952719846bc5ccd058249bb23d8a905"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = {7d 3d 2b 2b 24 7b}
		$s2 = {24 28 20 20 29}
		$s3 = {24 7B [1-10] 7D 20 20 2B 20 20 24}
		$s4 = {24 7B [1-10] 7D 24 7B}

	condition:
		2 of ($s*)
}
