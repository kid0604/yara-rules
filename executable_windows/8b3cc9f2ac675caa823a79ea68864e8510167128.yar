rule CN_Hacktool_1433_Scanner_Comp2
{
	meta:
		description = "Detects a chinese MSSQL scanner - component 2"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
		os = "windows"
		filetype = "executable"

	strings:
		$magic = { 4d 5a }
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword

	condition:
		($magic at 0) and all of ($s*)
}
