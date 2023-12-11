rule aspfile2
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "14efbc6cb01b809ad75a535d32b9da4df517ff29"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "response.write \"command completed success!\" " fullword ascii
		$s1 = "for each co in foditems " fullword ascii
		$s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
		$s19 = "<title>Hello! Welcome </title>" fullword ascii

	condition:
		all of them
}
