rule pos_uploader
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware"
		reference = "http://blogs.mcafee.com/mcafee-labs/analyzing-the-target-point-of-sale-malware"
		version = "0.1"
		description = "Testing the base64 encoded file in sys32"
		date = "01/30/2014"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd /c net start %s"
		$s2 = "ftp -s:%s"
		$s3 = "data_%d_%d_%d_%d_%d.txt"
		$s4 = "\\uploader\\"

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}
