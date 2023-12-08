import "pe"

rule APT1_MAPIGET
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting APT1 MAPIGET malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s\\Attachment.dat" wide ascii
		$s2 = "MyOutlook" wide ascii
		$s3 = "mail.txt" wide ascii
		$s4 = "Recv Time:" wide ascii
		$s5 = "Subject:" wide ascii

	condition:
		all of them
}
