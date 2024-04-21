import "pe"

rule find_bat_14335
{
	meta:
		description = "Find.bat using AdFind"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
		date = "2022-09-12"
		hash1 = "5a5c601ede80d53e87e9ccb16b3b46f704e63ec7807e51f37929f65266158f4c"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "find.exe" nocase wide ascii
		$s1 = "objectcategory" nocase wide ascii
		$s2 = "person" nocase wide ascii
		$s3 = "computer" nocase wide ascii
		$s4 = "organizationalUnit" nocase wide ascii
		$s5 = "trustdmp" nocase wide ascii

	condition:
		filesize <1000 and 1 of ($x*) and 4 of ($s*)
}
