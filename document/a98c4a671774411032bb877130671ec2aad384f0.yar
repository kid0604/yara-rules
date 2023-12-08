rule XDP_embedded_PDF : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
		weight = 1
		description = "Detects embedded PDF files using XDP format"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"

	condition:
		all of ($s*) and 1 of ($header*)
}
