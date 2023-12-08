import "pe"

rule APT1_GDOCUPLOAD
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 threat group uploading Google documents"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$str1 = "name=\"GALX\"" wide ascii
		$str2 = "User-Agent: Shockwave Flash" wide ascii
		$str3 = "add cookie failed..." wide ascii
		$str4 = ",speed=%f" wide ascii

	condition:
		3 of them
}
