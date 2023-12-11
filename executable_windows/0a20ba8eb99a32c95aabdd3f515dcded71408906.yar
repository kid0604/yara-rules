rule PortScanner
{
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "b381b9212282c0c650cb4b0323436c63"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Scan Ports Every"
		$s3 = "Scan All Possible Ports!"

	condition:
		all of them
}
