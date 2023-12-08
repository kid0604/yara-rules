rule CN_Honker_Webshell_Tuoku_script_oracle
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file oracle.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fc7043aaac0ee2d860d11f18ddfffbede9d07957"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii
		$s2 = "String user=\"oracle_admin\";" fullword ascii
		$s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii

	condition:
		filesize <7KB and all of them
}
