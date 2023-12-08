import "pe"

rule HKTL_EmbeddedPDF
{
	meta:
		description = "Detects Embedded PDFs which can start malicious content"
		author = "Tobias Michalski"
		reference = "https://twitter.com/infosecn1nja/status/1021399595899731968?s=12"
		date = "2018-07-25"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$x1 = "/Type /Action\n /S /JavaScript\n /JS (this.exportDataObject({" fullword ascii
		$s1 = "(This PDF document embeds file" fullword ascii
		$s2 = "/Names << /EmbeddedFiles << /Names" fullword ascii
		$s3 = "/Type /EmbeddedFile" fullword ascii

	condition:
		uint16(0)==0x5025 and 2 of ($s*) and $x1
}
